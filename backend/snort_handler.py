import os
import time
from backend.elastic_handler import ElasticHandler
from config import SNORT_LOG_PATH

HONEYPOT_SNORT_INDEX = "snort-logs"

class SnortHandler:
    def __init__(self):
        self.es_handler = ElasticHandler()
        self.log_path = SNORT_LOG_PATH or "/var/log/snort/alert.fast"
        self.last_inode = None
        print(f"[+] Initialized SnortHandler watching: {self.log_path}")

    def parse_alert_line(self, line):
        try:
            # Typical Snort fast alert format parsing
            parts = line.split("] [**] ")
            if len(parts) < 2:
                return None

            alert_info = parts[1].split(" [**]")[0]
            meta_data = parts[-1].strip()

            meta_parts = meta_data.split(" ")
            timestamp = meta_parts[0]
            src_ip, src_port = meta_parts[1].split(":")
            dst_ip, dst_port = meta_parts[3].split(":")

            return {
                "timestamp": timestamp,
                "alert": alert_info,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port
            }

        except Exception as e:
            print(f"[!] Failed to parse alert line: {e}")
            return None

    def parse_logs(self):
        try:
            with open(self.log_path, "r") as f:
                # Seek to end of file
                f.seek(0, os.SEEK_END)

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