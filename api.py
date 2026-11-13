import time
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from neo4j import GraphDatabase

# Import Stage 3 (LangGraph Swarm) and Stage 4 (MCP Remediation Tools)
from agent_swarm import build_aspm_graph, NEO4J_URI, NEO4J_AUTH
from aspm_mcp_server import verify_patch_in_sandbox, deliver_github_sub_pr

app = FastAPI(
    title="ASPM AI Remediation Engine API",
    description="GraphRAG & Multi-Agent Vulnerability Triage, Verification, and PR Gateway",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

aspm_swarm = build_aspm_graph()


# ==================== PYDANTIC SCHEMAS ====================

class RemediateRequest(BaseModel):
    cve_id: str = Field(..., example="CWE-601", description="The CVE or CWE ID to triage and remediate")
    base_branch: str = Field(
        default="legacy-v1",
        example="legacy-v1",
        description="Target branch for the Option B Sub-PR (e.g. 'legacy-v1' or 'main')",
    )


class RemediateResponse(BaseModel):
    cve_id: str
    service: str
    reachable: bool
    blast_radius: List[str]
    vuln_details: Dict[str, Any]
    triage_reasoning: str
    remediation_plan: Optional[str] = None
    code_patch: Optional[str] = None
    sandbox_verification: Optional[Dict[str, Any]] = None
    pr_delivery: Optional[Dict[str, Any]] = None
    execution_time_sec: float


# ==================== API ENDPOINTS ====================

@app.get("/api/v1/health")
def health_check():
    """Checks API readiness and verifies connectivity to Neo4j."""
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            session.run("RETURN 1")
        driver.close()
        return {"status": "healthy", "neo4j": "connected", "swarm_engine": "ready", "mcp_stage4": "ready"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection failed: {str(e)}")


@app.get("/api/v1/vulnerabilities")
def list_vulnerabilities():
    """Returns all vulnerabilities currently attached to microservices in Neo4j."""
    query = """
    MATCH (m:Microservice)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    RETURN v.id AS cve_id, m.name AS service, v.severity AS severity,
           v.type AS type, v.package AS package, v.description AS description
    ORDER BY v.severity DESC, v.id ASC
    """
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            records = session.run(query)
            vulns = [dict(r) for r in records]
        driver.close()
        return {"total": len(vulns), "vulnerabilities": vulns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query Neo4j: {str(e)}")


@app.post("/api/v1/remediate", response_model=RemediateResponse)
def remediate_vulnerability(request: RemediateRequest):
    """
    Triggers Stage 3 (Analyst -> Planner -> Coder) followed by
    Stage 4 MCP Tools (Sandbox Patch Verification -> Sub-PR Delivery).
    """
    start_time = time.time()

    initial_state = {
        "cve_id": request.cve_id.strip(),
        "service": "",
        "vuln_details": {},
        "blast_radius": [],
        "is_reachable": False,
        "reachable": False,
        "triage_reasoning": "",
        "rag_context": "",
        "remediation_plan": "",
        "code_patch": "",
    }

    try:
        final_state = aspm_swarm.invoke(initial_state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Swarm execution error: {str(e)}")

    if not final_state or final_state.get("service") == "unknown":
        raise HTTPException(
            status_code=404,
            detail=f"Vulnerability '{request.cve_id}' not found in the Neo4j architecture graph.",
        )

    is_reach = bool(final_state.get("is_reachable", final_state.get("reachable", True)))
    service = str(final_state.get("service", ""))
    cve_id = str(final_state.get("cve_id", request.cve_id))
    raw_patch = final_state.get("code_patch") or ""
    vuln_details = dict(final_state.get("vuln_details") or {})
    blast_radius = list(final_state.get("blast_radius") or [])
    triage_reasoning = str(final_state.get("triage_reasoning", ""))
    remediation_plan = final_state.get("remediation_plan") or ""

    sandbox_res = None
    pr_res = None

    # Execute Stage 4 MCP Tools if the vulnerability was reachable and a patch was generated
    if is_reach and raw_patch:
        sandbox_res = verify_patch_in_sandbox(
            cve_id=cve_id,
            service=service,
            raw_patch=raw_patch,
        )

        if sandbox_res.get("verified"):
            pr_res = deliver_github_sub_pr(
                cve_id=cve_id,
                service=service,
                severity=str(vuln_details.get("severity", "HIGH")),
                vuln_type=str(vuln_details.get("type", "SAST")),
                package=str(vuln_details.get("package", "unknown")),
                blast_radius=blast_radius,
                triage_reasoning=triage_reasoning,
                remediation_plan=remediation_plan,
                clean_patch=sandbox_res["clean_patch"],
                base_branch=request.base_branch.strip() or "main",
            )
            sandbox_res.pop("clean_patch", None)

    elapsed = round(time.time() - start_time, 2)

    return RemediateResponse(
        cve_id=cve_id,
        service=service,
        reachable=is_reach,
        blast_radius=blast_radius,
        vuln_details=vuln_details,
        triage_reasoning=triage_reasoning,
        remediation_plan=remediation_plan or None,
        code_patch=raw_patch or None,
        sandbox_verification=sandbox_res,
        pr_delivery=pr_res,
        execution_time_sec=elapsed,
    )