import os
import boto3
import uuid
import json
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ['TABLE_NAME']

def handler(event, context):
    userId = event['requestContext']['authorizer']['jwt']['claims']['username']
    id = str(uuid.uuid4())
    pk = f"USER#{userId}"
    sk = f"NOTE#{id}"
    table = dynamodb.Table(TABLE_NAME)
    item = {
            'sk': sk,
            'pk': pk,
            'id': id,
            'data': event['queryStringParameters']['data'],
            'userid': userId,
            'type': 'NOTE'
        }
    table.put_item(
        Item=item
    )
    
    return item