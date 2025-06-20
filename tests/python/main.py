import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import urllib3
import warnings

# Disable SSL warnings (since we're testing against a self-signed HTTPS endpoint)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

endpoint = 'http://localhost'
access_key = 'FAKEACCESS'
secret_key = 'FAKESECRET'
bucket = 'mybucket'
key = 'hello.txt'
body = b'Hello World from Python'  # Must be bytes

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
    verify=False  # Accept unverified SSL (self-signed certs)
)

# Create Bucket
try:
    s3.create_bucket(Bucket=bucket)
    print(f"Bucket '{bucket}' created.")
except ClientError as e:
    if e.response['Error']['Code'] == 'BucketAlreadyExists':
        print(f"Bucket '{bucket}' already exists.")
    else:
        print(f"CreateBucket error: {e.response['Error']['Message']}")

# Put Object
try:
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentLength=len(body))
    print(f"Object '{key}' uploaded.")
except ClientError as e:
    print(f"PutObject error: {e.response['Error']['Message']}")

# Get Object
try:
    response = s3.get_object(Bucket=bucket, Key=key)
    content = response['Body'].read().decode()
    print(f"Downloaded content: {content}")
except ClientError as e:
    print(f"GetObject error: {e.response['Error']['Message']}")

# List Objects
try:
    response = s3.list_objects(Bucket=bucket)
    contents = response.get('Contents', [])
    print("Objects in bucket:")
    for obj in contents:
        print(f"- {obj['Key']}")
except ClientError as e:
    print(f"ListObjects error: {e.response['Error']['Message']}")

# Delete Object
try:
    s3.delete_object(Bucket=bucket, Key=key)
    print(f"Object '{key}' deleted.")
except ClientError as e:
    print(f"DeleteObject error: {e.response['Error']['Message']}")

# Delete Bucket (recursive delete: first delete all objects, then the bucket)
try:
    # First list all objects
    response = s3.list_objects(Bucket=bucket)
    contents = response.get('Contents', [])
    for obj in contents:
        obj_key = obj['Key']
        try:
            s3.delete_object(Bucket=bucket, Key=obj_key)
            print(f"Deleted object: {obj_key}")
        except ClientError as e:
            print(f"Error deleting object {obj_key}: {e.response['Error']['Message']}")

    # Now delete the bucket
    s3.delete_bucket(Bucket=bucket)
    print(f"Bucket '{bucket}' deleted.")
except ClientError as e:
    print(f"DeleteBucket error: {e.response['Error']['Message']}")
