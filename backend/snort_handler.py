import os
import time
import re
from datetime import datetime

from backend.elastic_handler import ElasticHandler
from config import SNORT_LOG_PATH
from backend.enrich.iploc import enrich_ip  # Optional inline enrichment

HONEYPOT_SNORT_INDEX = "snort-logs"

class SnortHandler:
    def __init__(self):
        self.es_handler = ElasticHandler()
        self.log_path = SNORT_LOG_PATH or "/var/log/snort/alert.fast"
        print(f"[+] Initialized SnortHandler watching: {self.log_path}")

    def parse_alert_line(self, line):
        try:
            # Regex to extract relevant parts
            regex = (
                r"(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
                r"\[\*\*\] \[(?P<sid>[\d:]+)\] (?P<request_type>.*?) \[\*\*\] "
                r"\[Classification: (?P<classification>.*?)\] "
                r"\[Priority: (?P<priority>\d+)\] "
                r"\{(?P<protocol>\w+)\} (?P<src_ip>[\d\.]+):(?P<src_port>\d+) -> (?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)"
            )

            match = re.search(regex, line)
            if not match:
                return None

            data = match.groupdict()

            # Convert timestamp to ISO format (e.g. 2025-04-01T13:50:51.486Z)
            timestamp = datetime.strptime(data["timestamp"], "%m/%d-%H:%M:%S.%f")
            now = datetime.now()
            timestamp = timestamp.replace(year=now.year)  # Assume current year
            data["timestamp"] = timestamp.isoformat()

            # Optional IP Enrichment (comment out if not needed inline)
            src_geo = enrich_ip(data["src_ip"])
            dst_geo = enrich_ip(data["dst_ip"])

            if isinstance(src_geo, dict):
                data["src_city"] = src_geo.get("city")
                data["src_country"] = src_geo.get("country")
                data["src_location"] = src_geo.get("location")

            if isinstance(dst_geo, dict):
                data["dst_city"] = dst_geo.get("city")
                data["dst_country"] = dst_geo.get("country")
                data["dst_location"] = dst_geo.get("location")

            return data

        except Exception as e:
            print(f"[!] Failed to parse alert line: {e}")
            return None

    def parse_logs(self):
        try:
            with open(self.log_path, "r") as f:
                f.seek(0, os.SEEK_END)  # Start at end of file

                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue

                    alert_data = self.parse_alert_line(line)
                    if alert_data:
                        self.es_handler.store_log(HONEYPOT_SNORT_INDEX, alert_data)
                        print(f"[+] Snort alert sent to Elasticsearch: {alert_data}")

        except FileNotFoundError:
            print(f"[!] Snort log file not found: {self.log_path}")
        except Exception as e:
            print(f"[!] Error in Snort log parser: {e}")