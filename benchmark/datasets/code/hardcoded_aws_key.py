import boto3

AWS_ACCESS_KEY_ID = "MOCK_EXPOSED_AWS_ACCESS_KEY_ID_99"
AWS_SECRET_ACCESS_KEY = "mock_exposed_aws_secret_access_key_string_99"

def init_s3():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
