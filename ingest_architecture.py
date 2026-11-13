import os
import yaml
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "aspm_admin_123")

def find_manifest_files():
    """Finds Kubernetes manifest YAML files without double-counting release bundles."""
    primary_dir = "./online-boutique/kubernetes-manifests"
    fallback_dir = "./online-boutique/release"
    
    target_dir = primary_dir if os.path.exists(primary_dir) else fallback_dir
    yaml_files = []
    
    if os.path.exists(target_dir):
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    yaml_files.append(os.path.join(root, file))
                
    return yaml_files

def parse_kubernetes_manifests():
    """Parses manifest files to extract services and their _ADDR connections."""
    yaml_files = find_manifest_files()
    services = set()
    relationships = set()  # Using a set prevents duplicate (source, target) pairs

    print(f"Found {len(yaml_files)} manifest file(s) to parse...")

    for filepath in yaml_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                docs = yaml.safe_load_all(f)
                for doc in docs:
                    if not isinstance(doc, dict):
                        continue

                    if doc.get("kind") == "Deployment":
                        service_name = doc.get("metadata", {}).get("name")
                        if not service_name:
                            continue
                        services.add(service_name)

                        containers = (
                            doc.get("spec", {})
                               .get("template", {})
                               .get("spec", {})
                               .get("containers", [])
                        )
                        for container in containers:
                            for env in container.get("env", []):
                                env_name = env.get("name", "")
                                if env_name.endswith("_ADDR"):
                                    target_value = env.get("value", "")
                                    target_service = target_value.split(":")[0]
                                    if target_service:
                                        relationships.add((service_name, target_service))
        except Exception as e:
            print(f"Warning: Could not parse {filepath}: {e}")

    return list(services), list(relationships)

def build_graph(services, relationships):
    """Inserts microservice nodes and directional CALLS edges into Neo4j."""
    print("\nConnecting to Neo4j...")
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        with driver.session() as session:
            # Clear previous runs
            session.run("MATCH (n) DETACH DELETE n")

            # 1. Create Microservice nodes
            for service in services:
                session.run("CREATE (m:Microservice {name: $name})", name=service)
            print(f" -> Created {len(services)} Microservice nodes.")

            # 2. Create dependency edges
            for source, target in relationships:
                query = """
                MATCH (a:Microservice {name: $source})
                MATCH (b:Microservice {name: $target})
                MERGE (a)-[:CALLS]->(b)
                """
                session.run(query, source=source, target=target)
            print(f" -> Mapped {len(relationships)} API dependency relationships.")

if __name__ == "__main__":
    print("--- Starting Architecture Ingestion ---")
    services, relationships = parse_kubernetes_manifests()
    
    if not services:
        print("Error: No microservices found.")
    else:
        # This is the crucial step that was missing!
        build_graph(services, relationships)
        print("--- Successfully Built Security Knowledge Graph! ---")