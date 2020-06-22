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
    noteId = event['queryStringParameters']['noteid']
    pk = f"USER#{userId}"
    sk = f"NOTE#{noteId}"
    table = dynamodb.Table(TABLE_NAME)
    response = table.delete_item(Key={'pk': pk, 'sk': sk})
    return noteId