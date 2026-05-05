import boto3

dynamodb = boto3.resource('dynamodb', region_name='YOUR REGION NAME')
table = dynamodb.Table('ids-results')

print(f"Scanning and deleting all items in {table.name}...")

# Wiping the table using batch_writer for speed
deleted_count = 0
response = table.scan(
    # Fetch the Primary Key so we can delete an item
    ProjectionExpression="event_id" 
)

with table.batch_writer() as batch:
    for item in response.get('Items', []):
        batch.delete_item(
            Key={
                'event_id': item['event_id']
            }
        )
        deleted_count += 1

# Handle pagination if there is more than 1MB of data in the table
while 'LastEvaluatedKey' in response:
    response = table.scan(
        ProjectionExpression="event_id",
        ExclusiveStartKey=response['LastEvaluatedKey']
    )
    with table.batch_writer() as batch:
        for item in response.get('Items', []):
            batch.delete_item(
                Key={
                    'event_id': item['event_id']
                }
            )
            deleted_count += 1

print(f"Successfully deleted {deleted_count} items from the table.")