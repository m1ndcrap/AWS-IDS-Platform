import time
import os
import json
import boto3
import uuid
import glob
from datetime import datetime, timezone

# AWS Configuration
QUEUE_URL = 'YOUR SQS QUEUE URL FOR ids-events'
sqs = boto3.client('sqs', region_name='YOUR REGION NAME')

COLUMN_MAP = {
    'Dst Port': 'Destination Port',
    'Flow Duration': 'Flow Duration',
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Fwd Packet Length Max': 'Fwd Packet Length Max',
    'Fwd Packet Length Min': 'Fwd Packet Length Min',
    'Fwd Packet Length Mean': 'Fwd Packet Length Mean',
    'Fwd Packet Length Std': 'Fwd Packet Length Std',
    'Bwd Packet Length Max': 'Bwd Packet Length Max',
    'Bwd Packet Length Min': 'Bwd Packet Length Min',
    'Bwd Packet Length Mean': 'Bwd Packet Length Mean',
    'Bwd Packet Length Std': 'Bwd Packet Length Std',
    'Flow IAT Mean': 'Flow IAT Mean',
    'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max',
    'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Total': 'Fwd IAT Total',
    'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std',
    'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Total': 'Bwd IAT Total',
    'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std',
    'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Fwd PSH Flags': 'Fwd PSH Flags',
    'Bwd PSH Flags': 'Bwd PSH Flags',
    'Fwd URG Flags': 'Fwd URG Flags',
    'Bwd URG Flags': 'Bwd URG Flags',
    'Fwd Header Length': 'Fwd Header Length34',
    'Bwd Header Length': 'Bwd Header Length',
    'Fwd Packets/s': 'Fwd Packets/s',
    'Bwd Packets/s': 'Bwd Packets/s',
    'Packet Length Min': 'Min Packet Length',
    'Packet Length Max': 'Max Packet Length',
    'Packet Length Mean': 'Packet Length Mean',
    'Packet Length Std': 'Packet Length Std',
    'Packet Length Variance': 'Packet Length Variance',
    'FIN Flag Count': 'FIN Flag Count',
    'SYN Flag Count': 'SYN Flag Count',
    'RST Flag Count': 'RST Flag Count',
    'PSH Flag Count': 'PSH Flag Count',
    'ACK Flag Count': 'ACK Flag Count',
    'URG Flag Count': 'URG Flag Count',
    'CWR Flag Count': 'CWE Flag Count',
    'ECE Flag Count': 'ECE Flag Count',
    'Down/Up Ratio': 'Down/Up Ratio',
    'Average Packet Size': 'Average Packet Size',
    'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
    'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
    'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets': 'Subflow Fwd Packets',
    'Subflow Fwd Bytes': 'Subflow Fwd Bytes',
    'Subflow Bwd Packets': 'Subflow Bwd Packets',
    'Subflow Bwd Bytes': 'Subflow Bwd Bytes',
    'FWD Init Win Bytes': 'Init_Win_bytes_forward',
    'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'Active Mean': 'Active Mean',
    'Active Std': 'Active Std',
    'Active Max': 'Active Max',
    'Active Min': 'Active Min',
    'Idle Mean': 'Idle Mean',
    'Idle Std': 'Idle Std',
    'Idle Max': 'Idle Max',
    'Idle Min': 'Idle Min',
}

def clean_header(header_str):
    return header_str.strip()

def process_and_send(raw_row_dict):
    # Strip spaces from CSV column names
    clean_row = {k.strip(): v for k, v in raw_row_dict.items()}
    
    event_payload = {}

    for csv_col, model_col in COLUMN_MAP.items():
        val = clean_row.get(csv_col, 0.0)
        try:
            event_payload[model_col] = float(val) if val not in ['', None] else 0.0
        except ValueError:
            event_payload[model_col] = 0.0

    event_payload['event_id'] = f"live-{uuid.uuid4().hex[:8]}"
    event_payload['timestamp'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f"[DEBUG] Keys sent: {list(event_payload.keys())[:5]}")

    try:
        sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(event_payload))
        print(f"[SENT] {event_payload['event_id']} | Port: {event_payload.get('Destination Port')}")
    except Exception as e:
        print(f"[ERROR] {e}")

def watch_live_csv(file_path):
    print(f"Monitoring: {file_path}")

    with open(file_path, 'r') as f:
        header_line = f.readline()
        headers = [clean_header(h) for h in header_line.split(',')]
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue
            row_values = line.strip().split(',')

            if len(row_values) == len(headers):
                process_and_send(dict(zip(headers, row_values)))

if __name__ == '__main__':
    DAILY_DIR = 'YOUR CICFLOWMETER .CSV DIRECTORY PATH' # e.g. /home/kali/CICFlowMeter/data/daily/
    latest_csv = None

    while not latest_csv:
        csv_files = glob.glob(os.path.join(DAILY_DIR, "*.csv"))
        if csv_files: latest_csv = max(csv_files, key=os.path.getmtime)
        else: time.sleep(1)

    watch_live_csv(latest_csv)