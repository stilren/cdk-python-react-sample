import os
import boto3
import uuid
import json
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ['TABLE_NAME']

def handler(event, context):
    table = dynamodb.Table(TABLE_NAME)
    userId = event['requestContext']['authorizer']['jwt']['claims']['username']
    pk = f"USER#{userId}"
    response = table.query(
        KeyConditionExpression=Key('pk').eq(pk)
    )
    return response['Items']