from elasticsearch import Elasticsearch, helpers
import geoip2.database
import os
import requests

from config import ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD

# === Elasticsearch Client ===
es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
    verify_certs=False
)

# === Config ===
INDEX_NAME = "honeypot-logs"
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
GEOIP_DOWNLOAD_URL = "https://git.io/GeoLite2-City.mmdb"

# === Ensure GeoIP Database Exists ===
def download_geoip_db():
    if not os.path.exists(GEOIP_DB_PATH):
        print(f"[!] GeoLite2-City database not found at {GEOIP_DB_PATH}. Downloading...")
        try:
            response = requests.get(GEOIP_DOWNLOAD_URL)
            if response.status_code == 200:
                with open(GEOIP_DB_PATH, "wb") as f:
                    f.write(response.content)
                print("[✓] GeoLite2-City database downloaded successfully.")
            else:
                raise Exception(f"Failed to download. Status code: {response.status_code}")
        except Exception as e:
            print(f"[✗] Error downloading GeoLite2-City: {e}")
            exit(1)

# === Get City from IP ===
def get_city(ip, reader):
    try:
        response = reader.city(ip)
        return response.city.name or "Unknown"
    except:
        return "Unknown"

# === Enrich Documents ===
def enrich_documents(reader):
    results = helpers.scan(
        client=es,
        index=INDEX_NAME,
        query={"query": {"match_all": {}}},
        scroll="2m"
    )

    actions = []

    for doc in results:
        doc_id = doc["_id"]
        source = doc["_source"]
        ip = source.get("ip")

        # Skip if no IP or already enriched
        if not ip or "location" in source:
            continue

        city = get_city(ip, reader)
        print(f"[+] Enriching {ip} → {city}")

        actions.append({
            "_op_type": "update",
            "_index": INDEX_NAME,
            "_id": doc_id,
            "doc": {
                "location": {
                    "city": city
                }
            }
        })

        if len(actions) >= 500:
            helpers.bulk(es, actions)
            actions = []

    if actions:
        helpers.bulk(es, actions)

    print("[✓] City enrichment complete.")

# === Main ===
if __name__ == "__main__":
    download_geoip_db()
    reader = geoip2.database.Reader(GEOIP_DB_PATH)
    enrich_documents(reader)