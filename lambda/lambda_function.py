import boto3
import json
import joblib
import numpy as np
import os
from decimal import Decimal

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

BUCKET = 'aws-ids-platform'
MODEL_KEY = 'models/rf_model.joblib'
FEATURES_KEY = 'models/feature_cols.json'
CLASSES_KEY = 'models/classes.json'
TABLE_NAME = 'ids-results'
CONNECTIONS_TABLE = 'ids-connections'
TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
WS_ENDPOINT = 'https://229ixzo7u7.execute-api.us-east-2.amazonaws.com/prod'

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
        payload = json.loads(record['body'])

        features = [float(payload.get(col, 0)) for col in feature_cols]
        features = np.array(features).reshape(1, -1)

        prediction = model.predict(features)[0]
        probas = model.predict_proba(features)[0]
        threat_score = float(1 - probas[classes.index('BENIGN')])

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

        # Broadcast to WebSocket clients
        broadcast({
            'event_id': item['event_id'],
            'timestamp': item['timestamp'],
            'label': prediction,
            'prediction': 0 if prediction == 'BENIGN' else 1,
            'threat_score': str(round(threat_score, 4)),
            'attack_type': prediction
        })

    return {'statusCode': 200, 'body': 'OK'}