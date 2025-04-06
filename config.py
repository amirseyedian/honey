import os
from dotenv import load_dotenv

load_dotenv()

# Elasticsearch Config
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "elasticpass")
ELASTICSEARCH_INDEX_HONEYPOT = ("ELASTICSEARCH_INDEX_HONEYPOT","honeypot-logs")
ELASTICSEARCH_INDEX_SNORT = ("ELASTICSEARCH_INDEX_SNORT","snort-logs")
ELASTICSEARCH_VERIFY_CERTS = ("ELASTICSEARCH_VERIFY_CERTS","False")

# Snort Config
SNORT_LOG_PATH = os.getenv("SNORT_LOG_PATH", "/var/log/snort/snort.log")

# Webserver Config
WEB_SERVER_PORT = int(os.getenv("WEB_SERVER_PORT", 8080))

WEBPAGE_FOLDER = os.getenv("WEBPAGE_FOLDER", "www/")