import boto3
import json
import joblib
import numpy as np
import os
from decimal import Decimal

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

BUCKET = os.getenv('S3_BUCKET', 'aws-ids-platform')
MODEL_KEY = 'models/rf_model.joblib'
FEATURES_KEY = 'models/feature_cols.json'
CLASSES_KEY = 'models/classes.json'
TABLE_NAME = os.getenv('DYNAMODB_TABLE', 'ids-results')
CONNECTIONS_TABLE = os.getenv('DYNAMODB_CONNECTIONS_TABLE', 'ids-connections')
TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
WS_ENDPOINT = os.getenv('WS_ENDPOINT')

# Load at cold start
s3.download_file(BUCKET, MODEL_KEY, '/tmp/model.joblib')
s3.download_file(BUCKET, FEATURES_KEY, '/tmp/feature_cols.json')
s3.download_file(BUCKET, CLASSES_KEY, '/tmp/classes.json')

model = joblib.load('/tmp/model.joblib')

with open('/tmp/feature_cols.json') as f:
    feature_cols = json.load(f)

with open('/tmp/classes.json') as f:
    classes = json.load(f)

table = dynamodb.Table(TABLE_NAME)
connections_table = dynamodb.Table(CONNECTIONS_TABLE)
ws_client = boto3.client('apigatewaymanagementapi', endpoint_url=WS_ENDPOINT, region_name='us-east-2')

def broadcast(message):
    try:
        response = connections_table.scan()
        connections = response.get('Items', [])
        stale = []
        for conn in connections:
            try:
                ws_client.post_to_connection(
                    ConnectionId=conn['connectionId'],
                    Data=json.dumps(message).encode('utf-8')
                )
            except ws_client.exceptions.GoneException:
                stale.append(conn['connectionId'])
        for cid in stale:
            connections_table.delete_item(Key={'connectionId': cid})
    except Exception as e:
        print(f"Broadcast error: {e}")

def lambda_handler(event, context):
    for record in event['Records']:
        try:
            payload = json.loads(record['body'])
            clean_payload = {str(k).strip(): v for k, v in payload.items()}

            aligned_features = []
            missing_cols = []

            # Safely align features to the exact training order manually
            for col in feature_cols:
                clean_col = col.strip()
                
                # Patch for the CIC-IDS-2017 duplicate column bug
                if clean_col == 'Fwd Header Length55' and 'Fwd Header Length55' not in clean_payload:
                    val = clean_payload.get('Fwd Header Length34', 0.0)
                else:
                    val = clean_payload.get(clean_col, None)

                if val is None:
                    missing_cols.append(clean_col)
                    val = 0.0
                
                aligned_features.append(float(val))

            if missing_cols:
                print(f"[WARNING] Payload missing columns, defaulting to 0.0: {missing_cols}")

            # Force pure NumPy 32-bit float precision
            np_features = np.array(aligned_features, dtype=np.float32).reshape(1, -1)

            # Predict
            prediction = model.predict(np_features)[0]
            probas = model.predict_proba(np_features)[0]
            threat_score = float(1 - probas[classes.index('BENIGN')])

            print(f"[LOG] Event: {payload.get('event_id')} | Pred: {prediction} | Score: {threat_score:.4f}")

            # Database & Notifications
            item = {
                'event_id': payload['event_id'],
                'timestamp': payload['timestamp'],
                'label': prediction,
                'prediction': 0 if prediction == 'BENIGN' else 1,
                'threat_score': str(round(threat_score, 4)),
                'attack_type': prediction
            }

            table.put_item(Item=item)

            if prediction != 'BENIGN':
                sns.publish(
                    TopicArn=TOPIC_ARN,
                    Subject=f'Intrusion detected: {prediction}',
                    Message=f"Attack type: {prediction} | Threat score: {threat_score:.2%} | Event: {payload['event_id']} | Time: {payload['timestamp']}"
                )

            broadcast({
                'event_id': item['event_id'],
                'timestamp': item['timestamp'],
                'label': prediction,
                'prediction': 0 if prediction == 'BENIGN' else 1,
                'threat_score': str(round(threat_score, 4)),
                'attack_type': prediction
            })
            
        except Exception as e:
            print(f"[FATAL ERROR] Processing failed for record: {str(e)}")
            raise e

    return {'statusCode': 200, 'body': 'OK'}