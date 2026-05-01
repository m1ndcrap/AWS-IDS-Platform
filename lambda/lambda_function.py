import boto3
import json
import joblib
import numpy as np
import os

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

BUCKET = 'aws-ids-platform'
MODEL_KEY = 'models/rf_model.joblib'
FEATURES_KEY = 'models/feature_cols.json'
TABLE_NAME = 'ids-results'
TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# Load model at cold start
s3.download_file(BUCKET, MODEL_KEY, '/tmp/model.joblib')
s3.download_file(BUCKET, FEATURES_KEY, '/tmp/feature_cols.json')
model = joblib.load('/tmp/model.joblib')
with open('/tmp/feature_cols.json') as f:
    feature_cols = json.load(f)

table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    for record in event['Records']:
        payload = json.loads(record['body'])
        
        features = [float(payload.get(col, 0)) for col in feature_cols]
        features = np.array(features).reshape(1, -1)
        
        prediction = int(model.predict(features)[0])
        score = float(model.predict_proba(features)[0][1])
        
        table.put_item(Item = {
            'event_id': payload['event_id'],
            'prediction': prediction,
            'threat_score': str(round(score, 4)),
            'timestamp': payload['timestamp'],
            'label': 'DDoS' if prediction == 1 else 'BENIGN'
        })
        
        if prediction == 1:
            sns.publish(
                TopicArn = TOPIC_ARN,
                Subject = 'Intrusion detected',
                Message = f"Threat score: {score:.2%} | Event ID: {payload['event_id']} | Time: {payload['timestamp']}"
            )
    
    return {'statusCode': 200, 'body': 'OK'}