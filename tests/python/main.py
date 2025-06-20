import os
import time
import warnings

import boto3
import urllib3
from botocore.config import Config
from botocore.exceptions import ClientError

# Disable SSL warnings (self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

endpoint = 'http://localhost'
access_key = 'FAKEACCESS'
secret_key = 'FAKESECRET'
bucket = 'mybucket'

config = Config(
    s3={'addressing_style': 'path'},
    signature_version='s3v4',
    retries={'max_attempts': 3},
    parameter_validation=True
)

s3 = boto3.client(
    's3',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name='us-east-1',
    endpoint_url=endpoint,
    config=config,
    verify=False
)


def upload_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
        s3.put_object(Bucket=bucket, Key=key, Body=data, ContentLength=len(data))
        print(f"Uploaded: {key}")


def download_file(key, dest_path):
    response = s3.get_object(Bucket=bucket, Key=key)
    with open(dest_path, 'wb') as f:
        f.write(response['Body'].read())
    print(f"Downloaded: {dest_path}")


# Create bucket
try:
    s3.create_bucket(Bucket=bucket)
    print(f"Bucket '{bucket}' created.")
except ClientError as e:
    if e.response['Error']['Code'] == 'BucketAlreadyExists':
        print(f"Bucket '{bucket}' already exists.")
    else:
        print(f"CreateBucket error: {e.response['Error']['Message']}")

# Upload hello.txt
timestamp = str(int(time.time()))
text_key = f"{timestamp}_hello.txt"
body = b'Hello World from Python'
s3.put_object(Bucket=bucket, Key=text_key, Body=body, ContentLength=len(body))
print(f"Uploaded: {text_key}")

# Upload sample.png and sample.jpg
for file_name in ['sample.png', 'sample.jpg']:
    if os.path.isfile(file_name):
        random_key = f"{timestamp}_{file_name}"
        upload_file(file_name, random_key)
    else:
        print(f"Warning: File '{file_name}' not found. Skipping upload.")

# List objects
try:
    response = s3.list_objects(Bucket=bucket)
    contents = response.get('Contents', [])
    print("Objects in bucket:")
    for obj in contents:
        print(f"- {obj['Key']}")
except ClientError as e:
    print(f"ListObjects error: {e.response['Error']['Message']}")

# Download all objects
for obj in contents:
    key = obj['Key']
    local_path = f"downloaded_{os.path.basename(key)}"
    try:
        download_file(key, local_path)
    except ClientError as e:
        print(f"Download error for {key}: {e.response['Error']['Message']}")

# Delete all objects
for obj in contents:
    key = obj['Key']
    try:
        s3.delete_object(Bucket=bucket, Key=key)
        print(f"Deleted: {key}")
    except ClientError as e:
        print(f"DeleteObject error for {key}: {e.response['Error']['Message']}")

# Delete bucket
try:
    s3.delete_bucket(Bucket=bucket)
    print(f"Bucket '{bucket}' deleted.")
except ClientError as e:
    print(f"DeleteBucket error: {e.response['Error']['Message']}")
