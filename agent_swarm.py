import re
import json
import difflib
import subprocess
from pathlib import Path
from typing import TypedDict, List, Dict
from neo4j import GraphDatabase
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_chroma import Chroma
from langgraph.graph import StateGraph, END

# Database & Repository Configurations
NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "aspm_admin_123")
REPO_ROOT = Path(__file__).resolve().parent / "online-boutique"

# Uniform VRAM-Safe Limits (8GB GPU: stays 100% in VRAM, 0ms reload between Agent 1 & 2)
MAX_CTX = 4096
MAX_OUTPUT = 1500
MAX_RETRIES = 3


# 1. Define the Shared State across our Cyclic Agent Swarm
class AgentState(TypedDict, total=False):
    cve_id: str
    service: str
    vuln_details: dict
    blast_radius: List[str]
    is_reachable: bool
    retrieved_context: str
    target_files: List[str]
    triage_reasoning: str
    remediation_plan: str
    code_patch: str
    # Option A: Self-Healing Compiler Loop State Keys
    retry_count: int
    compiler_error: str
    sandbox_passed: bool


# 2. Helper Functions (Database Queries, Dynamic RAG, Multi-File Parser & Docker Sandbox)
def query_neo4j_blast_radius(cve_id: str):
    """Queries Neo4j to find the vulnerability details and all upstream callers."""
    with GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH) as driver:
        with driver.session() as session:
            vuln_query = """
            MATCH (m:Microservice)-[:HAS_VULNERABILITY]->(v:Vulnerability {id: $cve_id})
            RETURN m.name AS service, v.severity AS severity, v.type AS type,
                   v.package AS package, v.description AS description
            """
            record = session.run(vuln_query, cve_id=cve_id).single()
            if not record:
                return None, []

            service_name = record["service"]
            vuln_info = dict(record)

            path_query = """
            MATCH path = (caller:Microservice)-[:CALLS*1..5]->(target:Microservice {name: $service})
            RETURN DISTINCT caller.name AS caller
            """
            callers = [r["caller"] for r in session.run(path_query, service=service_name)]
            return vuln_info, callers


def retrieve_chroma_context(
    service: str,
    cve_id: str,
    package: str,
    vuln_type: str,
    description: str,
    max_rag_chars: int = 6500,
):
    """
    Dynamic, Token-Budgeted Scoped RAG:
    1. Builds the semantic query dynamically from the vulnerability's actual description (zero hardcoded keywords).
    2. Filters ChromaDB by microservice and vulnerability category (SCA vs SAST).
    3. Dynamically packs relevant chunks up to `max_rag_chars` (~1,600 tokens) to stay 100% VRAM-safe.
    """
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    vector_store = Chroma(
        collection_name="aspm_codebase",
        embedding_function=embeddings,
        host="localhost",
        port=8000,
    )

    category_target = "dependency_manifest" if vuln_type == "SCA" else "vulnerable_file"
    chroma_filter = {
        "$and": [
            {"service": {"$eq": service}},
            {"category": {"$eq": category_target}},
        ]
    }

    # 1. Purely dynamic semantic query driven by Neo4j vulnerability metadata
    dynamic_code_query = f"{cve_id} ({vuln_type}) in {package}: {description}"
    scored_candidates = vector_store.similarity_search_with_score(
        query=dynamic_code_query,
        k=6,
        filter=chroma_filter,
    )

    # Sort candidates so chunks matching the exact flagged filename in `package` come first, then by vector distance
    pkg_basename = package.split("/")[0].strip()
    scored_candidates.sort(
        key=lambda item: (
            0 if pkg_basename in item[0].metadata.get("source", "") else 1,
            item[1],  # Lower Chroma L2 distance = higher similarity
        )
    )

    # 2. Retrieve dynamic OWASP / Scanner remediation guidance first
    guidance_docs = vector_store.similarity_search(
        query=f"{cve_id} {vuln_type} {package} {description} remediation fix",
        k=1,
        filter={"category": {"$in": ["owasp_guideline", "scanner_report"]}},
    )

    # 3. Dynamically pack code chunks within our VRAM token budget (`max_rag_chars`)
    selected_service_docs = []
    current_chars = sum(len(d.page_content) for d in guidance_docs)

    for doc, score in scored_candidates:
        doc_len = len(doc.page_content)
        # Always include at least 1 code chunk; keep adding chunks while within budget
        if not selected_service_docs or (current_chars + doc_len <= max_rag_chars):
            selected_service_docs.append(doc)
            current_chars += doc_len

    all_docs = selected_service_docs + guidance_docs
    matched_files = sorted(
        list({d.metadata.get("source", "unknown").replace("\\", "/") for d in selected_service_docs})
    )
    if not matched_files:
        matched_files = [f"src/{service}/{package}"]

    print(
        f" -> Dynamic RAG Packed {len(selected_service_docs)} '{service}' chunk(s) "
        f"({current_chars}/{max_rag_chars} chars) across files: {matched_files}"
    )

    formatted_chunks = "\n\n---\n\n".join(
        [
            f"[EXACT REPOSITORY FILE: {d.metadata.get('source', '').replace(chr(92), '/')} | Category: {d.metadata.get('category')}]\n{d.page_content}"
            for d in all_docs
        ]
    )
    return formatted_chunks, matched_files


def extract_search_replace_blocks(llm_output: str, default_files: List[str]):
    """
    Extracts (file_path, search_block, replace_block) tuples.
    Supports explicit `<<<< SEARCH path/to/file` OR auto-detects the file from `default_files`.
    """
    pattern = re.compile(
        r"<{4,}\s*SEARCH(?:\s+([^\r\n]+))?\s*\r?\n(.*?)\r?\n={4,}\s*\r?\n(.*?)\r?\n>{4,}\s*REPLACE",
        re.DOTALL,
    )
    results = []
    for raw_path, s_block, r_block in pattern.findall(llm_output):
        clean_path = raw_path.strip().strip("`'\"[]") if raw_path else ""
        if clean_path.startswith("EXACT REPOSITORY FILE:"):
            clean_path = clean_path.replace("EXACT REPOSITORY FILE:", "").strip()
        clean_path = clean_path.replace("\\", "/")

        # If path wasn't provided or doesn't exist, auto-detect which retrieved file contains the SEARCH block
        if not clean_path or not (REPO_ROOT / clean_path).exists():
            detected_path = ""
            s_lines = [line.strip() for line in s_block.splitlines() if line.strip()]
            for candidate in default_files:
                cand_full = REPO_ROOT / candidate
                if cand_full.exists():
                    cand_text = cand_full.read_text(encoding="utf-8").replace("\r\n", "\n")
                    if s_block.replace("\r\n", "\n").strip() in cand_text:
                        detected_path = candidate
                        break
                    cand_lines = [line.strip() for line in cand_text.splitlines()]
                    for i in range(len(cand_lines)):
                        if cand_lines[i : i + len(s_lines)] == s_lines and s_lines:
                            detected_path = candidate
                            break
                    if detected_path:
                        break
            clean_path = detected_path or (default_files[0] if default_files else clean_path)

        results.append((clean_path, s_block, r_block))
    return results


def run_docker_go_compiler(service_dir: Path) -> tuple[bool, str]:
    """
    Runs `go vet ./...` inside an ephemeral Docker container (`golang:1.21-alpine`)
    with a persistent module cache volume (`aspm-go-cache`) for fast 1-2s builds.
    """
    abs_service_dir = str(service_dir.resolve())
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{abs_service_dir}:/workspace",
        "-v",
        "aspm-go-cache:/go/pkg/mod",
        "-v",
        "aspm-go-build-cache:/root/.cache/go-build",
        "-w",
        "/workspace",
        "golang:1.21-alpine",
        "go",
        "vet",
        "./...",
    ]
    print(f" -> [DOCKER SANDBOX] Spinning up `golang:1.21-alpine` container for `{service_dir.name}`...")
    res = subprocess.run(
        docker_cmd,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if res.returncode != 0:
        err_output = (res.stderr or res.stdout).strip()
        return False, err_output
    return True, ""


# 3. Define the Agent Nodes
def security_analyst_node(state: AgentState) -> AgentState:
    """Agent 1 (Llama-3): Queries Neo4j to calculate the Blast Radius and Triage."""
    print(f"\n[1/4] Security Analyst Agent (llama3) analyzing {state['cve_id']}...")
    vuln_info, callers = query_neo4j_blast_radius(state["cve_id"])

    if not vuln_info:
        raise ValueError(f"Vulnerability {state['cve_id']} not found in Neo4j.")

    service = vuln_info["service"]
    reachable = (service == "frontend") or ("frontend" in callers)

    llm = ChatOllama(model="llama3", temperature=0, num_ctx=MAX_CTX, num_predict=MAX_OUTPUT)
    prompt = f"""You are a Senior Application Security Analyst.
Vulnerability ID: {state['cve_id']}
Target Microservice: {service}
Severity: {vuln_info['severity']} ({vuln_info['type']})
Affected File/Package: {vuln_info['package']}
Description: {vuln_info['description']}
Upstream Microservices Calling '{service}': {callers}
Reachable from Public Frontend: {reachable}

Provide a concise 3-sentence Triage Assessment explaining the blast radius and whether this requires immediate remediation."""

    response = llm.invoke(prompt)
    print(f" -> Blast Radius Callers: {callers} | Reachable: {reachable}")

    return {
        **state,
        "service": service,
        "vuln_details": vuln_info,
        "blast_radius": callers,
        "is_reachable": reachable,
        "triage_reasoning": response.content,
        "retry_count": 0,
        "compiler_error": "",
        "sandbox_passed": False,
    }


def planner_node(state: AgentState) -> AgentState:
    """Agent 2 (Llama-3): Retrieves dynamic token-budgeted RAG context and drafts remediation plan."""
    print(f"\n[2/4] Planner Agent (llama3) drafting remediation plan for {state['service']}...")
    context, target_files = retrieve_chroma_context(
        state["service"],
        state["cve_id"],
        state["vuln_details"]["package"],
        state["vuln_details"]["type"],
        state["vuln_details"]["description"],
    )

    llm = ChatOllama(model="llama3", temperature=0, num_ctx=MAX_CTX, num_predict=MAX_OUTPUT)
    prompt = f"""You are a Principal Security Architect.
Vulnerability: {state['cve_id']} ({state['vuln_details']['type']}) in microservice '{state['service']}'
Flagged Package/Target: {state['vuln_details']['package']}
Description: {state['vuln_details']['description']}
Candidate Repository Files: {target_files}

Retrieved Repository Context from ChromaDB:
{context}

STRICT INSTRUCTIONS:
1. Reference the exact '[EXACT REPOSITORY FILE: ...]' path(s) from the context above.
2. Write a concise 3-bullet remediation plan (do NOT output full code blocks here, leave code to the Coder agent):
   - Which exact file path(s) ({target_files}) and specific lines matching the vulnerability description to modify.
   - How to fix it using ONLY standard built-in comparisons/checks without inventing non-existent helper functions or adding new imports.
   - Why upstream/downstream gRPC callers ({state['blast_radius']}) remain compatible."""

    response = llm.invoke(prompt)
    return {
        **state,
        "retrieved_context": context,
        "target_files": target_files,
        "remediation_plan": response.content,
    }


def coder_node(state: AgentState) -> AgentState:
    """Agent 3 (Qwen2.5-Coder): Generates surgical SEARCH/REPLACE blocks (supports 1 or multiple files + self-healing retries)."""
    attempt = state.get("retry_count", 0) + 1
    target_files = state.get("target_files") or [f"src/{state['service']}/{state['vuln_details']['package']}"]
    primary_file = target_files[0]
    prev_error = state.get("compiler_error", "")

    print(
        f"\n[3/4] Coder Agent (qwen2.5-coder:7b) generating SEARCH/REPLACE patch for {target_files} (Attempt {attempt}/{MAX_RETRIES})..."
    )

    feedback_section = ""
    if prev_error:
        print(f" -> [SELF-HEALING RETRY] Feeding previous Docker sandbox compiler error back to Qwen2.5-Coder:\n    {prev_error}")
        feedback_section = f"""
# CRITICAL SELF-HEALING FEEDBACK FROM PREVIOUS ATTEMPT (Attempt {attempt - 1} FAILED):
Your previous patch failed the Docker Compiler Sandbox with the following error:
{prev_error}

HOW TO FIX THIS COMPILER ERROR:
- Do NOT call undefined helper functions that do not exist in `{primary_file}`!
- Do NOT use packages unless they are already imported at the top of `{primary_file}`.
- Write the validation inline using basic built-in operators or functions already imported in the file.
"""

    llm = ChatOllama(model="qwen2.5-coder:7b", temperature=0, num_ctx=MAX_CTX, num_predict=MAX_OUTPUT)
    prompt = f"""You are an Autonomous Security Remediation Coder.
Vulnerability: {state['cve_id']} ({state['vuln_details']['type']}) in microservice '{state['service']}'
Candidate Repository Files: {target_files}
Flagged Component: {state['vuln_details']['package']}
Description: {state['vuln_details']['description']}

Remediation Plan:
{state['remediation_plan']}
{feedback_section}
Actual Repository File Content from ChromaDB:
{state['retrieved_context']}

STRICT INSTRUCTIONS:
1. DO NOT output a raw unified diff (no `+`, `-`, or `@@` line numbers).
2. Output one or more strict `<<<< SEARCH <file_path>` / `====` / `>>>> REPLACE` blocks.
3. The lines inside `<<<< SEARCH` MUST be copied character-for-character (including exact tabs/spaces) from the Actual Repository File Content above.
4. DO NOT call non-existent helper functions or unimported packages—your code will be compiled inside a real Docker container!

Use EXACTLY this format:

<<<< SEARCH {primary_file}
<exact original lines from file>
====
<patched replacement lines>
>>>> REPLACE"""

    response = llm.invoke(prompt)
    return {
        **state,
        "code_patch": response.content,
        "retry_count": attempt,
    }


def sandbox_qa_node(state: AgentState) -> AgentState:
    """Node 4 (Multi-File Docker Sandbox QA & Deterministic Difflib Engine):
    Applies all SEARCH/REPLACE blocks across 1 or more files, generates a 100% accurate
    multi-file unified diff via difflib, and runs real Docker compiler/manifest verification.
    """
    target_files = state.get("target_files") or []
    raw_llm_output = state.get("code_patch", "")
    attempt = state.get("retry_count", 1)

    print(f"\n[4/4] Sandbox QA Node verifying patch across {target_files} (Attempt {attempt}/{MAX_RETRIES})...")

    blocks = extract_search_replace_blocks(raw_llm_output, target_files)
    if not blocks:
        err = (
            "Output did not contain a valid `<<<< SEARCH ... ==== ... >>>> REPLACE` block. "
            "You MUST use the exact `<<<< SEARCH`, `====`, and `>>>> REPLACE` markers."
        )
        print(f" -> [SANDBOX FAIL] {err}")
        return {**state, "sandbox_passed": False, "compiler_error": err}

    originals_disk: Dict[Path, str] = {}
    originals_lf: Dict[str, str] = {}
    patched_lf_map: Dict[str, str] = {}

    for rel_path, search_block, replace_block in blocks:
        rel_path = rel_path.replace("\\", "/")
        full_file_path = REPO_ROOT / rel_path

        if not full_file_path.exists():
            err = f"Target file '{rel_path}' does not exist at {full_file_path}."
            print(f" -> [SANDBOX FAIL] {err}")
            return {**state, "sandbox_passed": False, "compiler_error": err}

        if rel_path not in originals_lf:
            raw_disk = full_file_path.read_text(encoding="utf-8")
            originals_disk[full_file_path] = raw_disk
            originals_lf[rel_path] = raw_disk.replace("\r\n", "\n")
            patched_lf_map[rel_path] = originals_lf[rel_path]

        current_lf = patched_lf_map[rel_path]
        s_clean = search_block.replace("\r\n", "\n").strip("\n")
        r_clean = replace_block.replace("\r\n", "\n").strip("\n")

        if s_clean == r_clean:
            err = f"Your SEARCH block and REPLACE block for `{rel_path}` are 100% identical (no-op change). You must actually modify the vulnerable line or version."
            print(f" -> [SANDBOX FAIL] {err}")
            return {**state, "sandbox_passed": False, "compiler_error": err}

        if s_clean in current_lf:
            patched_lf_map[rel_path] = current_lf.replace(s_clean, r_clean, 1)
        else:
            orig_lines = current_lf.splitlines()
            search_lines = [line.strip() for line in s_clean.splitlines() if line.strip()]
            matched_span = None
            for i in range(len(orig_lines)):
                window = [line.strip() for line in orig_lines[i : i + len(search_lines)]]
                if window == search_lines and search_lines:
                    matched_span = (i, i + len(search_lines))
                    break

            if matched_span:
                start_idx, end_idx = matched_span
                new_lines = orig_lines[:start_idx] + r_clean.splitlines() + orig_lines[end_idx:]
                patched_lf_map[rel_path] = "\n".join(new_lines) + ("\n" if current_lf.endswith("\n") else "")
            else:
                err = (
                    f"Could not find the `<<<< SEARCH` block inside `{rel_path}`. "
                    f"Copy the exact lines and indentation from `{rel_path}` in the provided context."
                )
                print(f" -> [SANDBOX FAIL] {err}")
                return {**state, "sandbox_passed": False, "compiler_error": err}

    # Generate 100% mathematically accurate unified diff across all modified files via difflib
    all_unified_diffs = []
    total_diff_lines = 0

    for rel_path, new_lf in patched_lf_map.items():
        old_lf = originals_lf[rel_path]
        diff_lines = list(
            difflib.unified_diff(
                old_lf.splitlines(keepends=True),
                new_lf.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                n=3,
            )
        )
        if diff_lines:
            total_diff_lines += len(diff_lines)
            file_diff = f"diff --git a/{rel_path} b/{rel_path}\n" + "".join(diff_lines)
            if not file_diff.endswith("\n"):
                file_diff += "\n"
            all_unified_diffs.append(file_diff)

    if not all_unified_diffs:
        err = "Generated diff is empty across all target files. Make sure the REPLACE block modifies the vulnerable code."
        print(f" -> [SANDBOX FAIL] {err}")
        return {**state, "sandbox_passed": False, "compiler_error": err}

    combined_unified_diff = "".join(all_unified_diffs)

    # Step B: Multi-File Docker Compiler & Manifest Verification in Temporary Sandbox
    try:
        go_service_dirs = set()
        for rel_path, new_lf in patched_lf_map.items():
            full_file_path = REPO_ROOT / rel_path

            # 1. JSON validation (e.g., package.json)
            if rel_path.endswith(".json"):
                try:
                    parsed_json = json.loads(new_lf)
                    if "dependencies" not in parsed_json:
                        raise ValueError("Missing `dependencies` key in package.json")
                    print(f" -> [DOCKER/MANIFEST PASS] `{rel_path}` JSON syntax and dependency structure verified!")
                except Exception as je:
                    err = f"Patched JSON file `{rel_path}` failed validation: {je}"
                    print(f" -> [SANDBOX COMPILER FAIL] {err}")
                    return {**state, "sandbox_passed": False, "compiler_error": err}

            # 2. Go source or go.mod manifest -> verify inside Docker `golang:1.21-alpine`
            if rel_path.endswith(".go") or rel_path.endswith("go.mod"):
                full_file_path.write_text(new_lf, encoding="utf-8", newline="\n")
                if rel_path.endswith(".go"):
                    go_service_dirs.add(full_file_path.parent)
                else:
                    abs_service_dir = str(full_file_path.parent.resolve())
                    mod_check = subprocess.run(
                        [
                            "docker", "run", "--rm",
                            "-v", f"{abs_service_dir}:/workspace",
                            "-w", "/workspace",
                            "golang:1.21-alpine",
                            "go", "mod", "edit", "-json",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if mod_check.returncode != 0:
                        err = f"Docker `go mod edit -json` failed on `{rel_path}`:\n{mod_check.stderr.strip()}"
                        print(f" -> [SANDBOX COMPILER FAIL] {err}")
                        return {**state, "sandbox_passed": False, "compiler_error": err}
                    print(f" -> [DOCKER SANDBOX PASS] `go mod edit -json` verified `{rel_path}` syntax inside `golang:1.21-alpine`!")

        # Run real Go compiler (`go vet ./...`) inside Docker for modified `.go` services
        for service_dir in go_service_dirs:
            passed, compiler_stderr = run_docker_go_compiler(service_dir)
            if not passed:
                err = f"Docker Go Compiler (`go vet ./...` in `golang:1.21-alpine`) failed on `{service_dir.name}`:\n{compiler_stderr}"
                print(f" -> [DOCKER COMPILER FAIL]\n{err}")
                return {**state, "sandbox_passed": False, "compiler_error": err}
            else:
                print(f" -> [DOCKER COMPILER PASS] `go vet ./...` compiled `{service_dir.name}` cleanly with 0 errors!")
    finally:
        # Always restore all original files on disk so git apply --check runs against a clean working tree
        for full_path, orig_content in originals_disk.items():
            full_path.write_text(orig_content, encoding="utf-8")

    wrapped_patch = f"```diff\n{combined_unified_diff}```"
    print(
        f" -> [SANDBOX QA PASSED] Deterministic diff generated ({len(all_unified_diffs)} file(s), {total_diff_lines} lines) with 0 compiler errors!"
    )
    return {
        **state,
        "code_patch": wrapped_patch,
        "sandbox_passed": True,
        "compiler_error": "",
    }


# 4. Conditional Routing Logic
def route_after_triage(state: AgentState):
    if state["is_reachable"]:
        return "planner"
    return END


def route_after_sandbox(state: AgentState):
    """Cyclic Self-Healing Edge: Loops back to `coder` if sandbox QA failed and retries remain."""
    if state.get("sandbox_passed", False):
        return END
    if state.get("retry_count", 0) < MAX_RETRIES:
        print(
            f" -> [LANGGRAPH SELF-HEALING LOOP] Routing back to `coder` node (Retry {state.get('retry_count')}/{MAX_RETRIES})..."
        )
        return "coder"
    print(" -> [LANGGRAPH MAX RETRIES REACHED] Exiting loop after maximum attempts.")
    return END


# 5. Build and Compile the Cyclic LangGraph Workflow
def build_aspm_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("security_analyst", security_analyst_node)
    workflow.add_node("planner", planner_node)
    workflow.add_node("coder", coder_node)
    workflow.add_node("sandbox_qa", sandbox_qa_node)

    workflow.set_entry_point("security_analyst")
    workflow.add_conditional_edges("security_analyst", route_after_triage)
    workflow.add_edge("planner", "coder")
    workflow.add_edge("coder", "sandbox_qa")
    workflow.add_conditional_edges("sandbox_qa", route_after_sandbox)

    return workflow.compile()


if __name__ == "__main__":
    print("=== Starting ASPM Cyclic Self-Healing Remediation Swarm ===")
    app = build_aspm_graph()

    initial_state = {
        "cve_id": "CWE-601",
        "service": "",
        "vuln_details": {},
        "blast_radius": [],
        "is_reachable": False,
        "retrieved_context": "",
        "target_files": [],
        "triage_reasoning": "",
        "remediation_plan": "",
        "code_patch": "",
        "retry_count": 0,
        "compiler_error": "",
        "sandbox_passed": False,
    }

    final_state = app.invoke(initial_state)

    print("\n================ FINAL SWARM OUTPUT ================")
    print(f"\n[TRIAGE ASSESSMENT ({final_state['service']})]:\n{final_state['triage_reasoning']}")
    print(f"\n[REMEDIATION PLAN]:\n{final_state['remediation_plan']}")
    print(f"\n[SANDBOX QA PASSED]: {final_state.get('sandbox_passed')} (Attempts: {final_state.get('retry_count')})")
    print(f"\n[DETERMINISTIC UNIFIED DIFF]:\n{final_state['code_patch']}")