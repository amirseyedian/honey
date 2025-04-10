import subprocess
from elasticsearch import Elasticsearch
from config import ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD

# Define index names
HONEYPOT_INDEX = "honeypot-logs"
SNORT_INDEX = "snort-logs"

class ElasticHandler:
    def __init__(self):
        # Initialize the Elasticsearch client
        self.es = Elasticsearch(
            [ELASTICSEARCH_HOST],
            basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            verify_certs=False
        )
        self.create_indexes()

    def create_indexes(self):
        """Ensure required indexes exist in Elasticsearch with proper mappings"""
        index_mappings = {
            "mappings": {
                "properties": {
                    "headers": {
                        "type": "object",
                        "dynamic": "false"  # Prevent subfields under headers
                    },
                    "source_ip": { "type": "ip" },
                    "destination_ip": { "type": "ip" },
                "location": { "type": "geo_point" },  #  Required for Kibana Maps
                    "timestamp": { "type": "date" },
                    "host": { "type": "keyword" },
                    "user_agent": { "type": "keyword" },
                    "accept": { "type": "keyword" },
                    "accept_language": { "type": "keyword" },
                    "connection": { "type": "keyword" },
                "content_type": { "type": "keyword" }
                # Add more explicitly mapped fields here as needed
                },
                "dynamic_templates": [
                    {
                        "headers_as_keywords": {
                            "path_match": "headers.*",
                            "mapping": {
                                "type": "keyword"
                            }
                        }
                    }
                ]
            }
        }

        # Check if the indexes already exist, and create them if they do not
        for index in [HONEYPOT_INDEX, SNORT_INDEX]:
            if not self.es.indices.exists(index=index):
                self.es.indices.create(index=index, body=index_mappings)
                print(f"Created index: {index}")
            else:
                print(f"Index {index} already exists.")
                
    def store_log(self, index, data):
        """Insert log into the specified Elasticsearch index"""
        if index not in [HONEYPOT_INDEX, SNORT_INDEX]:
            raise ValueError("Invalid index name!")
        self.es.index(index=index, document=data)



# Inside ElasticHandler class:
    def store_log(self, index, data):
        """Insert log into the specified Elasticsearch index"""
        if index not in [HONEYPOT_INDEX, SNORT_INDEX]:
            raise ValueError("Invalid index name!")
        
        self.es.index(index=index, document=data)

        # Run the IP location enrichment module after adding the log
        try:
            subprocess.run(["python", "-m", "backend.enrich.iploc"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to run enrichment script: {e}")