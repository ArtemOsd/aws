import base64
import logging
import os
import sys
from datetime import datetime
from time import sleep

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
import boto3
import pytest
import pytz
import requests
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
def sns_client(aws_session):
    return aws_session.client("sns")


@pytest.fixture(scope="module")
def sqs_client(aws_session):
    return aws_session.client("sqs")


@pytest.fixture(scope="module")
def iam_client(aws_session):
    return aws_session.client("iam")


@pytest.fixture
def get_instance(ec2_client):
    instance_info = ec2_client.describe_instances()
    for reservation in instance_info["Reservations"]:
        instance = reservation["Instances"][0]
        if "PublicIpAddress" in instance:
            return instance


def get_parameter(name):
    session = boto3.session.Session()
    ssm = session.client("ssm")
    parameter = ssm.get_parameter(Name=name, WithDecryption=True)
    return parameter["Parameter"]["Value"]


@pytest.fixture
def _base_url(get_instance):
    instance_address = get_instance["PublicIpAddress"]
    return f"http://{instance_address}/api"


@pytest.fixture
def base_headers():
    return {"Accept": "application/json"}


@pytest.fixture()
def upload_file(_base_url, base_headers):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "test.jpg")
    with open(file_path, "rb") as file:
        files = {"upfile": file}
        response = requests.post(_base_url, headers=base_headers, files=files)
        _id = response.json().get("id")
        uploaded_date = datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M")
    return _id, uploaded_date


def get_topic_type(sns_client, topic_arn):
    response = sns_client.get_topic_attributes(TopicArn=topic_arn)
    attributes = response["Attributes"]
    is_fifo = attributes.get("FifoTopic", "false").lower() == "true"
    return "FIFO" if is_fifo else "Standard"


def get_queue_type(queue_url):
    if queue_url.endswith(".fifo"):
        return "FIFO"
    else:
        return "Standard"


def check_encryption_status(response):
    attributes = response["Attributes"]
    kms_key_id = attributes.get("KmsMasterKeyId", "")
    if kms_key_id:
        return "enabled"
    else:
        return "disabled"


def check_sns_encryption_status(sns_client, topic_arn):
    response = sns_client.get_topic_attributes(TopicArn=topic_arn)
    return check_encryption_status(response)


def check_sqs_encryption_status(sqs_client, queue_url):
    response = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["All"]
    )
    return check_encryption_status(response)


def get_topic_tags(sns_client, topic_arn):
    response = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
    tags = response["Tags"]
    if tags:
        return tags


def get_queue_tags(sqs_client, queue_url):
    response = sqs_client.list_queue_tags(QueueUrl=queue_url)
    tags = response["Tags"]
    if tags:
        return tags


def check_dlq_settings(sqs_client, queue_url):
    response = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["RedrivePolicy"]
    )
    redrive_policy = response.get("Attributes", {}).get("RedrivePolicy", None)

    if redrive_policy:
        logging.info(f"DLQ is configured: {redrive_policy}")
        return "yes"
    else:
        logging.info("No Dead-Letter Queue is configured for this queue.")
        return "no"


def send_test_message(sqs_client, queue_url):
    """Send a test message to the SQS queue."""
    response = sqs_client.send_message(
        QueueUrl=queue_url, MessageBody="Hello, this is a test message!"
    )
    return response


def receive_test_message(sqs_client, queue_url):
    """Receive messages from the SQS queue."""
    response = sqs_client.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=3, WaitTimeSeconds=10
    )
    return response


def get_allowed_actions_by_role_and_permission(iam, part_role_name, part_policy_name):
    roles = iam.list_roles()
    for role in roles["Roles"]:
        if part_role_name in role["RoleName"].lower():
            attached_policies = iam.list_attached_role_policies(
                RoleName=role["RoleName"]
            )
            for policy in attached_policies["AttachedPolicies"]:
                if part_policy_name in policy["PolicyName"]:
                    policy_arn = policy["PolicyArn"]
                    policy_version = iam.get_policy(PolicyArn=policy_arn)["Policy"][
                        "DefaultVersionId"
                    ]
                    policy_document = iam.get_policy_version(
                        PolicyArn=policy_arn, VersionId=policy_version
                    )
                    document = policy_document["PolicyVersion"]["Document"]
                    actions = []
                    for statement in document["Statement"]:
                        if statement["Effect"] == "Allow":
                            if isinstance(statement["Action"], str):
                                actions.append(statement["Action"])
                            elif isinstance(statement["Action"], list):
                                actions.extend(statement["Action"])
                    return actions


def list_roles(iam_client):
    """List all IAM roles and their associated policies."""
    try:
        # Paginator to handle the retrieval of all roles
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                logging.info(f"Role Name: {role['RoleName']}")
                logging.info("Attached Policies:")
                list_attached_policies(iam_client, role["RoleName"])
                logging.info("Inline Policies:")
                list_inline_policies(iam_client, role["RoleName"])
                logging.info("\n")
    except Exception as e:
        logging.info(f"Error retrieving roles: {str(e)}")


def list_attached_policies(iam_client, role_name):
    """List attached policies for a given role."""
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page["AttachedPolicies"]:
                logging.info(
                    f"  Policy Name: {policy['PolicyName']} (ARN: {policy['PolicyArn']})"
                )
    except Exception as e:
        logging.info(
            f"Error retrieving attached policies for role {role_name}: {str(e)}"
        )


def list_inline_policies(iam_client, role_name):
    """List inline policies for a given role."""
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page["PolicyNames"]:
                logging.info(f"  Policy Name: {policy_name}")
    except Exception as e:
        logging.info(f"Error retrieving inline policies for role {role_name}: {str(e)}")


@pytest.fixture()
def subscribe_random_email(_base_url, base_headers):
    import time

    random_value = int(time.time())
    email = f"test_{random_value}@myunrealgmail.com"
    url = _base_url + "/notification/" + email
    response = requests.post(url, headers=base_headers)
    assert response.status_code == 200
    return email


@pytest.fixture(scope="module")
def ec2_client(aws_session):
    return aws_session.client("ec2")


@pytest.fixture(scope="module")
def mail_creds():
    import os
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

    SCOPES = ["https://mail.google.com/"]
    creds = None
    script_dir = os.path.dirname(os.path.abspath(__file__))
    token_file_path = os.path.join(script_dir, "token.json")
    creds_file_path = os.path.join(script_dir, "credentials.json")
    # The file token.json stores the user's access and refresh tokens.
    if os.path.exists(token_file_path):
        creds = Credentials.from_authorized_user_file(token_file_path, SCOPES)
    # If there are no valid credentials, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:

            flow = InstalledAppFlow.from_client_secrets_file(
                creds_file_path, SCOPES
            )  # credentials.json is downloaded from Google Developer Console
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(token_file_path, "w") as token:
            token.write(creds.to_json())
    return creds


def get_full_message(service, user_id, msg_id):
    message = (
        service.users()
        .messages()
        .get(userId=user_id, id=msg_id, format="raw")
        .execute()
    )
    msg_str = base64.urlsafe_b64decode(message["raw"].encode("ASCII"))
    import email

    mime_msg = email.message_from_bytes(msg_str)

    if mime_msg.is_multipart():
        # iterate over email parts
        for part in mime_msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition"))
            if ctype == "text/plain" and "attachment" not in cdispo:
                body = part.get_payload(decode=True)  # decode
                logging.info("Body:" + str(body.decode()))
                return body.decode()
            elif ctype == "text/html":
                html_body = part.get_payload(decode=True)
                logging.info("HTML Body:" + str(html_body.decode()))
                return html_body.decode()
    else:
        # not multipart - i.e. plain text, no attachments, keeping it simple
        body = mime_msg.get_payload(decode=True)
        logging.info("Body:" + str(body.decode()))
        return body.decode()


def mark_as_read(service, user_id, msg_id):
    # Remove the 'UNREAD' label from the message
    service.users().messages().modify(
        userId=user_id, id=msg_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()
    logging.info(f"Message {msg_id} marked as read.")


def list_messages(mail_creds, q="is:unread", user_id="me"):
    from googleapiclient.discovery import build

    service = build("gmail", "v1", credentials=mail_creds)
    results = (
        service.users()
        .messages()
        .list(userId=user_id, labelIds=["INBOX"], q=q)
        .execute()
    )
    messages = results.get("messages", [])
    data = []
    if not messages:
        logging.info("No messages found.")
    else:
        logging.info("Message snippets:")
        for message in messages:
            logging.info("Reading message ID:", message["id"])
            data.append(get_full_message(service, user_id, message["id"]))
            if message:
                mark_as_read(service, user_id, message["id"])
    return data


@pytest.fixture()
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        yield browser
        browser.close()


def get_confirmation_link_from_email(mail_creds, user_id="me", is_mark_as_read=False):
    from time import sleep

    sleep(3)
    from googleapiclient.discovery import build

    service = build("gmail", "v1", credentials=mail_creds)
    q = "is:unread AWS sns -in:chats"
    results = (
        service.users()
        .messages()
        .list(userId=user_id, labelIds=["INBOX"], q=q)
        .execute()
    )
    messages = results.get("messages", [])
    if not messages:
        logging.error("No messages found.")
    else:
        logging.info("Message snippets:")
        for message in messages:
            logging.info("Reading message ID:", message["id"])
            if is_mark_as_read:
                mark_as_read(service, user_id, message["id"])
            body = get_full_message(service, user_id, message["id"])
            return extract_links(body)[0]


def extract_links(html_text):
    # Regular expression to find links
    import re

    link_pattern = re.compile(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"')

    # Find all occurrences of the pattern
    links = link_pattern.findall(html_text)

    return links


@pytest.fixture()
def upload_images_to_s3_with_http(_base_url, base_headers):
    url = _base_url + "/image"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "test.jpg")
    with open(file_path, "rb") as file:
        files = {"upfile": file}
        response = requests.post(url, headers=base_headers, files=files)
        assert response.status_code == 200
        sleep(1)


@pytest.fixture()
def delete_file_via_http(_base_url, base_headers):
    response = requests.get(_base_url + "/image", headers=base_headers)
    _id = response.json()[0]["id"]
    url = _base_url + "/image/" + str(_id)
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.text.strip() == '"Image is deleted"'
    sleep(1)
