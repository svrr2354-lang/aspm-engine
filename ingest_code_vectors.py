import os
import json
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter

REPO_PATH = "./online-boutique"
VULN_REPORT_PATH = "vulnerability_report.json"

# Directories we NEVER want to crawl in any codebase
IGNORED_DIRS = {".git", "node_modules", "vendor", "bin", "obj", "__pycache__", ".venv", "test", "tests"}

# 1. Standard Polyglot Dependency Manifests
MANIFEST_FILENAMES = {"go.mod", "package.json", "requirements.txt", "pom.xml", "build.gradle"}
MANIFEST_EXTENSIONS = (".csproj",)

# 2. API Contracts (The "Edges" between microservices)
CONTRACT_EXTENSIONS = (".proto", ".graphql")
CONTRACT_FILENAMES = {"swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml"}

# 3. Microservice Entrypoint / Route Handler patterns
EDGE_CODE_KEYWORDS = ("handler", "server", "route", "controller", "client", "main", "index", "app")
CODE_EXTENSIONS = (".go", ".js", ".py", ".java", ".cs")


def load_scanner_targets(report_path):
    """Extracts affected services and filenames dynamically from the scanner JSON."""
    affected_services = set()
    flagged_files = set()

    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            vulns = json.load(f)
            for v in vulns:
                if v.get("service"):
                    affected_services.add(v["service"].lower())
                if v.get("file"):
                    flagged_files.add(v["file"].lower())
                elif v.get("package"):
                    flagged_files.add(v["package"].lower())

    return affected_services, flagged_files


def discover_target_files(repo_path, report_path):
    """
    Dynamic Crawling Algorithm:
    Crawls any repository and selects strictly:
      - API Contracts (.proto / OpenAPI)
      - Dependency Manifests (go.mod, package.json, .csproj, etc.)
      - Scanner-flagged vulnerable files
      - Edge/Handler files inside affected microservices
    """
    affected_services, flagged_files = load_scanner_targets(report_path)
    discovered_files = []

    print(f"Crawling repository: {repo_path}...")
    print(f" -> Scanner-flagged services: {sorted(affected_services)}")
    print(f" -> Scanner-flagged files/packages: {sorted(flagged_files)}")

    for root, dirs, files in os.walk(repo_path):
        # Prune ignored directories in-place for fast crawling
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        rel_root = os.path.relpath(root, repo_path).replace("\\", "/").lower()

        for file in files:
            file_lower = file.lower()
            full_path = os.path.join(root, file)
            category = None

            # Rule 1: Is it an API Contract?
            if file_lower in CONTRACT_FILENAMES or file_lower.endswith(CONTRACT_EXTENSIONS):
                category = "api_contract"

            # Rule 2: Is it a Dependency Manifest?
            elif file_lower in MANIFEST_FILENAMES or file_lower.endswith(MANIFEST_EXTENSIONS):
                category = "dependency_manifest"

            # Rule 3: Was this exact file flagged by a scanner (Semgrep/Trivy)?
            elif file_lower in flagged_files:
                category = "vulnerable_file"

            # Rule 4: Is it an Edge/Handler code file inside an affected microservice?
            elif file_lower.endswith(CODE_EXTENSIONS):
                in_affected_service = any(srv in rel_root for srv in affected_services)
                is_edge_file = any(kw in file_lower for kw in EDGE_CODE_KEYWORDS)
                if in_affected_service and is_edge_file:
                    category = "service_edge_code"

            if category:
                discovered_files.append((full_path, category))

    return discovered_files


def ingest_into_chroma(discovered_files, report_path):
    """Chunks and embeds the dynamically discovered files + scanner reports + OWASP guidelines."""
    print("\nInitializing Ollama embedding model (`nomic-embed-text`)...")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")

    print("Connecting to ChromaDB on localhost:8000...")
    vector_store = Chroma(
        collection_name="aspm_codebase",
        embedding_function=embeddings,
        host="localhost",
        port=8000,
    )

    vector_store.reset_collection()
    print(" -> Cleared old 'aspm_codebase' collection from ChromaDB.")


    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,          # Fits complete Go/Java/Python functions (~50-60 lines)
        chunk_overlap=250,        # Preserves variable/header context across splits
        separators=[
            "\nfunc ",            # Go function boundary
            "\ndef ",             # Python function boundary
            "\nclass ",           # Class boundary
            "\n\n",
            "\n",
            " ",
        ],
    )

    texts = []
    metadatas = []
    ids = []

    # 1. Chunk and prepare discovered repository files
    for file_path, category in discovered_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if not content.strip():
                continue

            chunks = text_splitter.split_text(content)
            rel_path = os.path.relpath(file_path, REPO_PATH).replace("\\", "/")

            # Dynamically extract service name (e.g., "src/checkoutservice/go.mod" -> "checkoutservice")
            parts = rel_path.split("/")
            service_name = parts[1] if len(parts) > 2 and parts[0] == "src" else "global"

            for idx, chunk in enumerate(chunks):
                texts.append(chunk)
                metadatas.append({
                    "source": rel_path,
                    "category": category,
                    "service": service_name,
                })
                ids.append(f"file::{rel_path}::chunk_{idx}")

            print(f" -> [{category} | service={service_name}] {rel_path} ({len(chunks)} chunks)")
        except Exception as e:
            print(f"Warning: Skipped {file_path}: {e}")

    # 2. Embed the Vulnerability Scanner Reports (JSON Chunks)
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            vulns = json.load(f)
        for v in vulns:
            vuln_text = (
                f"Vulnerability {v['cve_id']} ({v['severity']}) in service '{v['service']}'. "
                f"Scanner: {v['scanner']} ({v['type']}). Package/File: {v['package']} ({v['version']}). "
                f"Description: {v['description']}"
            )
            texts.append(vuln_text)
            metadatas.append({"source": report_path, "category": "scanner_report", "service": v["service"]})
            ids.append(f"vuln::{v['service']}::{v['cve_id']}")
        print(f" -> [scanner_report] Embedded {len(vulns)} vulnerability report entries")

    # 3. Embed OWASP Remediation Guidelines
    owasp_guidelines = [
        {
            "id": "owasp::cwe-601",
            "text": "OWASP Remediation (CWE-601 / HTTP Handler Hardening in Go): Validate all incoming redirect URLs against a strict allowlist of relative paths. Never pass unvalidated user input directly into http.Redirect or response headers.",
        },
        {
            "id": "owasp::sca-upgrades",
            "text": "OWASP Dependency Remediation (Go & Node.js SCA): Upgrade vulnerable packages in go.mod (e.g., golang.org/x/text >= v0.3.7) or package.json (replace deprecated 'grpc' with '@grpc/grpc-js') and verify gRPC .proto contracts remain compatible.",
        },
    ]
    for guide in owasp_guidelines:
        texts.append(guide["text"])
        metadatas.append({"source": "OWASP_Knowledge_Base", "category": "owasp_guideline"})
        ids.append(guide["id"])
    print(f" -> [owasp_guideline] Embedded {len(owasp_guidelines)} secure coding guidelines")

    # Push everything to Chroma using deterministic IDs (prevents duplicates on re-runs!)
    print(f"\nPushing {len(texts)} total chunks to ChromaDB...")
    vector_store.add_texts(texts=texts, metadatas=metadatas, ids=ids)
    print(f" -> Successfully stored {len(texts)} vectors in ChromaDB!")


if __name__ == "__main__":
    print("--- Starting Dynamic Vector DB Ingestion ---")
    discovered = discover_target_files(REPO_PATH, VULN_REPORT_PATH)
    if not discovered:
        print("Error: No target files found. Ensure ./online-boutique exists.")
    else:
        print(f"\nDynamically discovered {len(discovered)} high-value target files.")
        ingest_into_chroma(discovered, VULN_REPORT_PATH)
        print("--- Dynamic Vector DB Ingestion Complete! ---")