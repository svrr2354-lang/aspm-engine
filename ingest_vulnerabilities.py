import json
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "aspm_admin_123")

def load_vulnerabilities(filepath="vulnerability_report.json"):
    """Reads the mock vulnerability JSON report."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def ingest_to_neo4j(vulnerabilities):
    """Links Vulnerability nodes to existing Microservice nodes in Neo4j."""
    print(f"Connecting to Neo4j to ingest {len(vulnerabilities)} vulnerabilities...")
    
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        with driver.session() as session:
            for vuln in vulnerabilities:
                query = """
                // 1. Find the existing microservice
                MATCH (m:Microservice {name: $service})
                
                // 2. Create the Vulnerability node
                MERGE (v:Vulnerability {id: $cve_id})
                SET v.severity = $severity,
                    v.description = $description,
                    v.scanner = $scanner,
                    v.type = $type,
                    v.package = $package
                
                // 3. Link them together
                MERGE (m)-[:HAS_VULNERABILITY]->(v)
                """
                
                session.run(query, 
                            service=vuln["service"],
                            cve_id=vuln["cve_id"],
                            severity=vuln["severity"],
                            description=vuln["description"],
                            scanner=vuln["scanner"],
                            type=vuln["type"],
                            package=vuln["package"])
                
                print(f" -> Attached {vuln['cve_id']} to {vuln['service']}")

if __name__ == "__main__":
    print("--- Starting Vulnerability Ingestion ---")
    try:
        vuln_data = load_vulnerabilities()
        ingest_to_neo4j(vuln_data)
        print("--- Successfully Layered Vulnerabilities onto the Graph! ---")
    except FileNotFoundError:
        print("Error: Could not find vulnerability_report.json. Did you create it in the root folder?")