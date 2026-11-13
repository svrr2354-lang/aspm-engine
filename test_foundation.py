from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

print("--- Starting ASPM Foundation Verification ---")

# 1. Test Neo4j Connection
print("\n[1/3] Testing Neo4j Graph Database connection...")
URI = "bolt://localhost:7687"
AUTH = ("neo4j", "aspm_admin_123")
try:
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        print(" SUCCESS: Connected to Neo4j Graph DB!")
except Exception as e:
    print(f" FAILED: Could not connect to Neo4j. Error: {e}")

# 2. Test Ollama Embedding Model Connection
print("\n[2/3] Testing Local Ollama Embedding Model (`nomic-embed-text`)...")
embeddings = None
try:
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    vector = embeddings.embed_query("Test security code snippet for ASPM")
    print(f" SUCCESS: Generated embedding vector! Length of vector: {len(vector)}")
except Exception as e:
    print(f" FAILED: Could not reach Ollama. Is Ollama running? Error: {e}")

# 3. Test Chroma Vector DB Connection (Docker service on port 8000)
print("\n[3/3] Testing Chroma Vector Database...")
try:
    if embeddings is None:
        raise RuntimeError("Skipping Chroma test because Ollama embeddings are unavailable.")

    vector_store = Chroma(
        collection_name="test_collection",
        embedding_function=embeddings,
        host="localhost",
        port=8000,
    )
    vector_store.add_texts(
        texts=["func checkout() { fmt.Println('vulnerable code') }"],
        metadatas=[{"source": "test_file.go"}],
        ids=["foundation-check-1"],
    )
    results = vector_store.similarity_search("vulnerable code", k=1)
    print(f" SUCCESS: Chroma vector DB is working! Retrieved match: {results[0].page_content}")
except Exception as e:
    print(f" FAILED: Chroma DB error: {e}")

print("\n--- Foundation Verification Complete ---")
