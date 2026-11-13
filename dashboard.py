import streamlit as st
import requests
import pandas as pd

API_BASE_URL = "http://127.0.0.1:8080/api/v1"

st.set_page_config(
    page_title="ASPM Autonomous Remediation Command Center",
    page_icon="🛡️",
    layout="wide",
)

# Header & Architecture Banner
st.title("🛡️ ASPM Autonomous Remediation Command Center")
st.caption(
    "Hybrid GraphRAG (Neo4j + ChromaDB) • Multi-Agent LangGraph Swarm (`llama3` + `qwen2.5-coder:7b`) • MCP GitHub Sub-PR Engine"
)

# Sidebar Configuration & Health Status
with st.sidebar:
    st.header("⚙️ Engine Configuration")
    api_url = st.text_input("FastAPI Gateway URL", value=API_BASE_URL)
    base_branch = st.text_input(
        "Target Base Branch (Option B Sub-PR)",
        value="legacy-v1",
        help="The branch on your GitHub fork that autonomous Sub-PRs will target.",
    )

    st.divider()
    st.subheader("🔌 System Health")
    if st.button("Check Gateway Status", use_container_width=True):
        try:
            res = requests.get(f"{api_url}/health", timeout=5)
            if res.status_code == 200:
                data = res.json()
                st.success(f"Gateway: {data.get('status').upper()}")
                st.json(data)
            else:
                st.error(f"Health check returned {res.status_code}")
        except Exception as e:
            st.error(f"Cannot reach FastAPI at {api_url}: {e}")

    st.divider()
    st.markdown(
        "**Pipeline Stages:**\n"
        "1. **Stage 1:** Neo4j Topology + ChromaDB Vectors\n"
        "2. **Stage 2:** FastAPI Orchestration Gateway\n"
        "3. **Stage 3:** 3-Agent Swarm (Analyst → Planner → Coder)\n"
        "4. **Stage 4:** MCP Sandbox Check & GitHub Sub-PR"
    )


# Fetch Vulnerabilities from FastAPI / Neo4j
@st.cache_data(ttl=10)
def fetch_vulnerabilities(base_url: str):
    resp = requests.get(f"{base_url}/vulnerabilities", timeout=10)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


try:
    vulns = fetch_vulnerabilities(api_url)
except Exception as e:
    st.error(
        f"⚠️ Could not connect to FastAPI Gateway at `{api_url}`. "
        f"Make sure `uvicorn api:app --reload --port 8080` is running! Error: {e}"
    )
    st.stop()

# Top KPI Metrics Row
total_vulns = len(vulns)
critical_high = sum(1 for v in vulns if v.get("severity") in ("CRITICAL", "HIGH"))
sast_count = sum(1 for v in vulns if v.get("type") == "SAST")
sca_count = sum(1 for v in vulns if v.get("type") == "SCA")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Flagged Alerts", total_vulns)
col2.metric("Critical / High Severity", critical_high)
col3.metric("SAST (Code Flaws)", sast_count)
col4.metric("SCA (Dependency CVEs)", sca_count)

st.divider()

# Vulnerability Inventory Table
st.subheader("📊 Neo4j Microservice Vulnerability Inventory")
if not vulns:
    st.info("No vulnerabilities found in Neo4j. Run `python ingest_vulnerabilities.py` first.")
    st.stop()

df = pd.DataFrame(vulns)[["cve_id", "severity", "type", "service", "package", "description"]]
st.dataframe(df, use_container_width=True, hide_index=True)

st.divider()

# Interactive Remediation Trigger Section
st.subheader("🚀 Autonomous GraphRAG Triage & Sub-PR Remediation")

cve_options = [f"{v['cve_id']}  |  {v['service']} ({v['type']} - {v['severity']})" for v in vulns]
selected_label = st.selectbox("Select a Vulnerability Alert to Remediate:", options=cve_options)
selected_cve_id = selected_label.split("  |  ")[0].strip()

if st.button("⚡ Execute 3-Agent Swarm & Open GitHub Sub-PR", type="primary", use_container_width=True):
    with st.status(
        f"Running Autonomous ASPM Pipeline for `{selected_cve_id}` (Targeting `{base_branch}`)...",
        expanded=True,
    ) as status:
        st.write("🔍 **[Stage 3 - Agent 1]** `llama3` querying Neo4j for microservice blast radius & reachability...")
        st.write("📐 **[Stage 3 - Agent 2]** `llama3` retrieving metadata-scoped ChromaDB chunks & drafting architectural plan...")
        st.write("💻 **[Stage 3 - Agent 3]** `qwen2.5-coder:7b` generating unified remediation patch...")
        st.write("🛠️ **[Stage 4 - MCP Server]** Verifying patch headers & delivering Sub-PR to GitHub...")

        try:
            payload = {"cve_id": selected_cve_id, "base_branch": base_branch}
            response = requests.post(f"{api_url}/remediate", json=payload, timeout=180)
            if response.status_code != 200:
                status.update(label="❌ Pipeline Execution Failed", state="error", expanded=True)
                st.error(f"FastAPI Error ({response.status_code}): {response.text}")
                st.stop()

            result = response.json()
            status.update(
                label=f"✅ Completed in {result['execution_time_sec']}s! Service: `{result['service']}` | Reachable: `{result['reachable']}`",
                state="complete",
                expanded=False,
            )
            st.session_state["last_result"] = result
        except Exception as e:
            status.update(label="❌ Request Failed", state="error", expanded=True)
            st.error(f"Error calling `/api/v1/remediate`: {e}")
            st.stop()

# Display Remediation Results if available
if "last_result" in st.session_state:
    res = st.session_state["last_result"]

    st.markdown(f"### 📋 Remediation Report: `{res['cve_id']}` on `{res['service']}`")

    # Blast Radius & Reachability Summary Cards
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Target Service", res["service"])
    m2.metric("Publicly Reachable", "YES ⚠️" if res["reachable"] else "NO (Isolated)")
    callers = ", ".join(res.get("blast_radius") or []) or "Direct Public Entrypoint"
    m3.metric("Upstream Blast Radius", callers)
    m4.metric("Execution Time", f"{res['execution_time_sec']} sec")

    # Stage 4 PR Delivery Banner
    pr_info = res.get("pr_delivery") or {}
    sandbox_info = res.get("sandbox_verification") or {}

    if pr_info.get("pr_url"):
        st.success(
            f"🎉 **Live GitHub Sub-PR Opened!** Branch `{pr_info.get('branch_name')}` ➔ `{pr_info.get('base_branch')}`  |  "
            f"**[🔗 Click Here to View Pull Request on GitHub]({pr_info['pr_url']})**"
        )
    elif pr_info:
        st.info(f"📁 **Local Remediation Bundle Saved:** {pr_info.get('message')}")

    # Tabbed Output View for Agent Reasoning, Plan, Patch, and MCP Metadata
    tab1, tab2, tab3, tab4 = st.tabs([
        "🧠 1. Analyst Triage & Blast Radius",
        "📐 2. Architectural Plan",
        "💻 3. Generated Diff Patch",
        "🛠️ 4. MCP Sandbox & PR Telemetry",
    ])

    with tab1:
        st.markdown("#### Security Analyst Assessment (`llama3`)")
        st.write(res.get("triage_reasoning", "No triage reasoning generated."))
        st.markdown("#### Vulnerability Metadata (Neo4j)")
        st.json(res.get("vuln_details", {}))

    with tab2:
        st.markdown("#### Principal Architect Remediation Plan (`llama3`)")
        st.markdown(res.get("remediation_plan") or "*No remediation plan generated (vulnerability unreachable).*")

    with tab3:
        st.markdown("#### Unified Code Patch (`qwen2.5-coder:7b`)")
        raw_patch = res.get("code_patch") or ""
        # Strip outer markdown fences if present so st.code renders cleanly
        clean_display = raw_patch.replace("```diff", "").replace("```", "").strip()
        st.code(clean_display or "No patch generated.", language="diff")

    with tab4:
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### MCP Tool 1: `verify_patch_in_sandbox`")
            st.json(sandbox_info)
        with col_b:
            st.markdown("#### MCP Tool 2: `deliver_github_sub_pr`")
            st.json(pr_info)