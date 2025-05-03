## Honeypot Monitoring and Intrusion Detection System

### Overview

This project is a lightweight webserver honeypot framework integrated with Snort for intrusion detection and the ELK Stack for centralized logging and visualization. The system is designed to monitor and log malicious activity targeting exposed services while providing a modular and extensible backend.

• HTTP webserver acting as a honeypot.


• Snort for packet-level intrusion detection.

• Elasticsearch for storing and indexing logs.

• Kibana for visualizing honeypot and Snort events.

• MinIO for file storage (optional if dealing with file captures).

• FastAPI for internal APIs.

• Log enrichment support (optional GeoIP).



### Features
• Passive webserver honeypot logging suspicious HTTP requests.

• Snort log parsing and integration.

• Real-time log indexing to Elasticsearch.

• Full visualization dashboard using Kibana.

• Clean project structure with separate modules for parsing, storage, and enrichment.

• Optional GeoIP enrichment for external IPs.

• Modular thread-based execution system for honeypot, Snort, and enrichment tasks.
### Requirements
• Python 3.10

• Snort installed and configured

• Elasticsearch and Kibana (self-hosted or via Docker)

## Installation and Deployment

### Prepare backend applications
1. Install Elasticsearch
Get Keys
```shell
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
```
Add to repository
```shell
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
```
Install elasticsearch
```shell
sudo apt update && sudo apt install elasticsearch
```
Elasticsearch configuration
>sudo nano /etc/elasticsearch/elasticsearch.yml

2. Install Kibana
Get keys
```shell
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```
Add repo
```shell
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
```
INstall kibana
```shell
sudo apt update && sudo apt install kibana
```

# OR
Deploy backend using docker
edit docker env and add custom password to ELK then start docker compose process.
```shell
docker-compose up -d
```

3. start and enable services
```shell
sudo systemctl enable elasticsearch.service
sudo systemctl enable kibana.service
sudo systemctl start elasticsearch
sudo systemctl start kibana
```
4. Configure kibana and attach to elasticsearch
reset elastic password if you like and get kibana auth token
```shell
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```
5. insert the token into kibana in http://localhost:5601

6. login to kibana dashboards
Deploy Honeypot server

1. Clone the repository
```shell
git clone honey
```

2. create a virtual environment
```shell
python3.10 -m venv venv
source venv/bin/activate
pip install -r requirements
```
3. Configure the `.env` file:
- Add elasticsearch url, credentials 
- Set snort log path (/var/log/snort/alerts.fast)

4. Start the server
```shell
python honey.py
```
Honeypot server will be online on port 8080
#### Optional
You can setup a reverse proxy like nginx for better performance

## Access monitoring dashboard

Import the custom dashboard
```shell
curl -X POST "http://localhost:5601/api/kibana/dashboards/import?exclude=index-pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  --user elastic:changeme \
  --data-binary "@dashboards/dashboard.json"
```
Login and Open Dashboards and Refresh
## Snort Installation and configuration

Install snort IDS/IPS tool
```sh
sudo apt install snort
```

After installtion enable service
```sh
sudo systemctl enable snort
```
link snort alert log file to the alert file in project root
```sh
sudo ln /var/log/snort/snort.alert.fast /home/<your-user>/honey/alert.fast
```
Now any new alert/log will be synced to the alert file in honey root directory

### Snort Inline Mode (IPS) Setup

To enable Snort to actively block malicious traffic (IPS mode), follow these steps:
1.	Ensure NFQUEUE support is available:

```sh
snort --daq-list | grep nfq
```

You should see: nfq(v3): NFQ packet acquisition module

2.	Add iptables rules to send traffic to NFQUEUE:
```sh
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
```

3.	Change rule keyword from Alert to Drop, Add a drop rule in /etc/snort/rules/custom.rules:

For example: To block access to HTTP port 80
```drop tcp any any -> any 80 (msg:"[TEST] Blocked HTTP"; sid:1000001; rev:1;)```


4.	Edit snort.conf to include your local rules:
Make sure this line is uncommented:

>include $RULE_PATH/local.rules

5.	Run Snort in inline mode:

```sh
sudo snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf
```


Snort will now inspect and drop matching packets according to your rules.
