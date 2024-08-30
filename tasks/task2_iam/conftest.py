import os

import boto3
import pytest
from dotenv import load_dotenv

# Load the .env file
load_dotenv()

# Get the credentials from the .env file
access_key = os.getenv("AWS_ACCESS_KEY_ID")
secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region = os.getenv("AWS_REGION")


@pytest.fixture(scope="module")
def aws_session():
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    return session


@pytest.fixture(scope="module")
def iam_client(aws_session):
    return aws_session.client("iam")
