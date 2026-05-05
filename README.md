# AWS IDS Platform

### Cloud-Native AI-Powered Intrusion Detection System

A production-grade, cloud-native intrusion detection system built on AWS that captures live network traffic, extracts flow features, applies ML-based multi-class threat classification, and delivers email alerts and real-time feed on dashboards.

## Architecture

```
Live Network Traffic (Kali Linux VM)
           |
    CICFlowMeter (packet capture -> 76 flow features)
           |
    live_watcher.py (CSV watcher -> SQS)
           |
    Amazon SQS (ids-events queue)
           |
    AWS Lambda (ids-inference)
           |
    Random Forest Classifier (trained on CICIDS 2017)
           |
    -----------------------
    |                     |
DynamoDB              Amazon SNS
(ids-results)      (email alerts)
    |
API Gateway -> React Dashboard
```

## Tech Stack

| Layer             | Technology                                 |
| ----------------- | ------------------------------------------ |
| Cloud             | AWS                                        |
| Data Ingestion    | Amazon S3, AWS Glue                        |
| Event Queue       | Amazon SQS                                 |
| Inference         | AWS Lambda (Python 3.11)                   |
| ML Model          | Scikit-learn Random Forest                 |
| Model Training    | Amazon SageMaker                           |
| Storage           | Amazon DynamoDB                            |
| Alerting          | Amazon SNS                                 |
| API               | Amazon API Gateway (REST + WebSocket)      |
| Dashboard         | HTML/CSS/JS with WebSocket                 |
| Packet Capture    | CICFlowMeter (Java)                        |
| Attack Simulation | Kali Linux, hping3, hydra, nmap, slowloris |

## ML Model

- Dataset: CICIDS 2017
- Training samples: 650,000+ network flows (sampled and balanced)
- Algorithm: Random Forest Classifier
- Features: 76 network flow features
- Classes: 9 attack categories

| Class        | Description                                    |
| ------------ | ---------------------------------------------- |
| BENIGN       | Normal traffic                                 |
| DDoS         | Distributed Denial of Service                  |
| DoS          | Denial of Service (Slowloris, Hulk, GoldenEye) |
| PortScan     | Network reconnaissance                         |
| BruteForce   | SSH/FTP credential attacks                     |
| WebAttack    | SQL injection, XSS                             |
| Infiltration | Network infiltration                           |
| Heartbleed   | OpenSSL CVE-2014-0160                          |
| Other        | Miscellaneous attack patterns                  |

**Classification Report:**

```
              precision    recall  f1-score   support

      BENIGN       1.00      1.00      1.00      6000
  BruteForce       0.99      0.95      0.97      1000
        DDoS       1.00      1.00      1.00      5715
         DoS       1.00      1.00      1.00      6000
  Heartbleed       1.00      1.00      1.00      1000
Infiltration       1.00      1.00      1.00      1000
       Other       0.99      0.99      0.99      1000
    PortScan       1.00      1.00      1.00      5579
   WebAttack       0.95      0.99      0.97      1000

    accuracy                           1.00     28294
   macro avg       0.99      0.99      0.99     28294
weighted avg       1.00      1.00      1.00     28294
```

## AWS Services

| Service                          | Purpose                                                   |
| -------------------------------- | --------------------------------------------------------- |
| S3 (`aws-ids-platform`)          | Raw CICIDS CSVs, processed features, model artifacts      |
| Glue (`ids-etl-all-attacks`)     | ETL pipeline (cleans and normalizes raw CSVs)             |
| SageMaker                        | Notebook-based model training and evaluation              |
| SQS (`ids-events`)               | Decouples traffic ingestion from inference                |
| Lambda (`ids-inference`)         | Loads model, runs inference, writes results, sends alerts |
| Lambda (`ids-api-query`)         | REST API handler for dashboard data                       |
| Lambda (`ids-websocket-handler`) | WebSocket connection manager                              |
| DynamoDB (`ids-results`)         | Stores all classified events                              |
| DynamoDB (`ids-connections`)     | Tracks active WebSocket connections                       |
| SNS (`ids-alerts`)               | Email alerts on detected intrusions                       |
| API Gateway (REST)               | `/results` endpoint for dashboard                         |
| API Gateway (WebSocket)          | Real-time event push to dashboard                         |
| CloudWatch                       | Lambda monitoring and logging                             |

## Live Capture Pipeline

The live capture pipeline uses CICFlowMeter on Kali Linux to extract real network flow features from live traffic, which are then fed into the AWS inference pipeline.

```
Kali Linux (attacker)
    │
    |-- CICFlowMeter captures on eth0
    |       |---- Writes flow CSV every n seconds
    │
    |-- live_watcher.py
            |-- Watches CSV for new rows
            |-- Maps CICFlowMeter columns
            |-- Sends JSON payload to SQS
```

### Setup on Kali Linux

```bash
# Install Java 8
wget "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk" -O openjdk-8.tar.gz
sudo mkdir -p /opt/java
sudo tar -xzf openjdk-8.tar.gz -C /opt/java/
export JAVA_HOME=/opt/java/jdk8u482-b08
export PATH=$JAVA_HOME/bin:$PATH

# Clone and build CICFlowMeter
git clone https://github.com/ahlashkari/CICFlowMeter.git
cd CICFlowMeter
mvn install:install-file \
  -Dfile=/home/kali/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
  -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
mvn -f pom.xml install

# Run CICFlowMeter GUI
sudo java -Djava.library.path=/usr/lib \
  -jar target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar
# Click 'Load', then select 'eth0' or 'any', then click 'Start'

# In a second terminal, run the live watcher
pip3 install boto3
python3 live_watcher.py
```

### Configure AWS credentials on Kali

```bash
pip3 install awscli boto3
aws configure
# Enter your AWS Access Key ID, Secret, Region
```

## Attack Simulation

### Lab Setup

| VM                      | IP  | Role                               |
| ----------------------- | --- | ---------------------------------- |
| Kali Linux              | IP1 | Attacker + packet capture          |
| Ubuntu 22.04            | IP2 | Primary target                     |
| Metasploitable 2 Linux  | IP3 | Vulnerable target (FTP, SSH, HTTP) |
| Metasploitable 3 Ubuntu | IP4 | Vulnerable web apps                |

All VMs on VMware NAT network.

### Confirmed Working Attacks

**DoS**

```bash
# Apache Benchmark flood
ab -n 5000 -c 50 http://IP2/

# Slowloris
slowloris IP2 -s 300

# Other
ab -n 5000 -c 50 http://IP2/
```

**BruteForce**

```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/fasttrack.txt ssh://IP2

# FTP brute force against Metasploitable 2
hydra -l msfadmin -P /usr/share/wordlists/fasttrack.txt ftp://IP3
```

**PortScan**

```bash
# Service version scan (generates classifiable flows)
nmap -sV -T2 -p 22,80,443,3306,8080 IP2
```

## Statistical Traffic Simulator

For demo purposes without requiring the VM lab setup, I have made a python simulator script that generates statistically realistic network flows based on the CICIDS feature distributions.

```bash
cd simulator
python3 simulate.py
```

Simulates mixed traffic with configurable attack probability and burst mode:

- 70% BENIGN
- 8% DDoS
- 7% DoS
- 6% PortScan
- 5% BruteForce
- 4% WebAttack

## Dashboard

Real-time threat monitoring dashboard with WebSocket live feed.

Features:

- Live event feed via WebSocket (no polling)
- Total events, threats detected, benign traffic, avg threat score
- Per-attack-type color-coded event log
- Interactive donut chart with hover tooltips
- Clickable legend filters (multi-select)
- Sort by threat score or timestamp (ascending/descending)
- Flash animation on new threat detection

Running locally:

```bash
cd dashboard
python -m http.server 8080
# Open http://localhost:8080
```

---

## Project Structure

```
aws-ids-platform/
|-- dashboard/
|   |-- index.html          # Real-time threat monitoring dashboard
|-- data/
|   |-- README.md           # Dataset documentation
|-- glue/
│   |-- etl_job.py          # AWS Glue ETL script
|-- lambda/
|   |-- lambda_function.py  # Inference Lambda function
|-- notebooks/
|   |-- ids_training.ipynb  # SageMaker training notebook
|-- scripts
|   |-- clear_db.py         # Clear table
    |-- live_watcher        # Copy CICFlowMeter CSV data into SQS pipeline
|-- simulator/
|   |-- simulate.py         # Statistical traffic simulator
|-- README.md
```

## Key Design Decisions

Why Random Forest over deep learning?
Random Forest provides excellent performance on tabular network flow data, is interpretable, loads fast in Lambda cold starts, and avoids scipy/tensorflow dependency issues in serverless environments.

Why SQS between capture and inference?
Decoupling ingestion from inference allows the system to handle traffic bursts without dropping events. SQS acts as a buffer in case Lambda is throttled then our messages queue up and are processed in order.

Why WebSocket over polling?
The dashboard uses API Gateway WebSocket API to push events from Lambda directly to connected clients the moment a flow is classified, achieving true real-time detection visualization without polling overhead.

Flow-based vs packet-based IDS:
This system operates at the flow level (like NetFlow/IPFIX) rather than deep packet inspection. Flow-based analysis scales better, requires no payload decryption, and is how most enterprise IDS/IPS systems operate. The tradeoff is that encrypted attack payloads cannot be inspected, which is why most web attacks are harder to classify.

## Limitations

- Flow-based classification cannot inspect encrypted payloads (HTTPS)
- CICFlowMeter requires minimum flow duration to extract meaningful features... This means that very short-lived attacks (sub-millisecond SYN scans) may not generate enough data
- Model trained on 2017 data; modern attack variants may have different flow characteristics
- Lambda cold starts add ~4-10 seconds latency on first inference after idle period
