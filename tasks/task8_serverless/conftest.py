import base64
import json
import logging
import os
from datetime import datetime

import boto3
import pymysql
import pytest
import pytz
import requests
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder

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
def ec2_client(aws_session):
    return aws_session.client("ec2")


@pytest.fixture(scope="module")
def ec2(aws_session):
    return aws_session.resource("ec2")


@pytest.fixture(scope="module")
def rds_client(aws_session):
    return aws_session.client("rds")


@pytest.fixture(scope="module")
def iam_client(aws_session):
    return aws_session.client("iam")


@pytest.fixture(scope="module")
def lambda_client(aws_session):
    return aws_session.client("lambda")


@pytest.fixture(scope="module")
def dynamodb_client(aws_session):
    return aws_session.client("dynamodb")


@pytest.fixture(scope="module")
def get_certificate(aws_session):
    cert_path = "cert.pem"
    ssm = aws_session.client("ssm")
    parameter_name_with_key = None
    response = ssm.describe_parameters()
    for parameter in response["Parameters"]:
        if "/ec2/keypair/key-" in parameter["Name"]:
            parameter_name_with_key = parameter["Name"]
    response = ssm.get_parameter(Name=parameter_name_with_key, WithDecryption=True)
    parameter_value = response["Parameter"]["Value"].replace("\r\n", "\n")
    with open(cert_path, "w", encoding="utf-8") as f:
        f.write(parameter_value)
    yield cert_path
    import os

    if os.path.exists(cert_path):
        os.remove(cert_path)


@pytest.fixture(scope="module")
def get_instance_module(ec2_client):
    instance_info = ec2_client.describe_instances()
    for reservation in instance_info["Reservations"]:
        instance = reservation["Instances"][0]
        if "PublicIpAddress" in instance:
            return instance


@pytest.fixture
def get_instance(ec2_client):
    instance_info = ec2_client.describe_instances()
    for reservation in instance_info["Reservations"]:
        instance = reservation["Instances"][0]
        if "PublicIpAddress" in instance:
            return instance


@pytest.fixture
def get_rds_instance(rds_client):
    response = rds_client.describe_db_instances()
    return response["DBInstances"][0]


def can_ec2_access_rds(ec2_client, ec2_instance_id, rds_client, rds_instance_id):
    ec2_response = ec2_client.describe_instances(InstanceIds=[ec2_instance_id])
    ec2_sg_ids = [
        sg["GroupId"]
        for sg in ec2_response["Reservations"][0]["Instances"][0]["SecurityGroups"]
    ]

    rds_response = rds_client.describe_db_instances(
        DBInstanceIdentifier=rds_instance_id
    )
    rds_sg_ids = [
        sg["VpcSecurityGroupId"]
        for sg in rds_response["DBInstances"][0]["VpcSecurityGroups"]
    ]

    for rds_sg_id in rds_sg_ids:
        sg_details = ec2_client.describe_security_groups(GroupIds=[rds_sg_id])
        for sg in sg_details["SecurityGroups"]:
            for permission in sg["IpPermissions"]:
                if (
                    permission["FromPort"] <= 3306 <= permission["ToPort"]
                    and "tcp" in permission["IpProtocol"]
                ):
                    for source_sg in permission.get("UserIdGroupPairs", []):
                        if source_sg["GroupId"] in ec2_sg_ids:
                            logging.info(
                                f"EC2 instance {ec2_instance_id} can access RDS instance {rds_instance_id} via SG {rds_sg_id}"
                            )
                            return True

    logging.info(
        f"EC2 instance {ec2_instance_id} cannot access RDS instance {rds_instance_id}"
    )
    return False


def is_rds_in_private_subnet(ec2_client, rds_client, rds_instance_id):
    rds_response = rds_client.describe_db_instances(
        DBInstanceIdentifier=rds_instance_id
    )
    subnets = rds_response["DBInstances"][0]["DBSubnetGroup"]["Subnets"]
    for subnet in subnets:
        subnet_id = subnet["SubnetIdentifier"]
        route_tables = ec2_client.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )

        for rt in route_tables["RouteTables"]:
            for route in rt["Routes"]:
                if "GatewayId" in route and "igw-" in route["GatewayId"]:
                    logging.info(
                        f"Subnet {subnet_id} is not private; it has access to the Internet."
                    )
                    return False
        logging.info(f"Subnet {subnet_id} is private; no internet access found.")
    return True


def get_rds_instance_type(rds_client, rds_instance_id):
    response = rds_client.describe_db_instances(DBInstanceIdentifier=rds_instance_id)
    return response["DBInstances"][0]["DBInstanceClass"]


def get_parameter(name):
    session = boto3.session.Session()
    ssm = session.client("ssm")
    parameter = ssm.get_parameter(Name=name, WithDecryption=True)
    return parameter["Parameter"]["Value"]


@pytest.fixture(scope="module")
def dynamodb_resource(aws_session):
    return boto3.resource("dynamodb", region_name=aws_session.region_name)


@pytest.fixture(scope="module")
def db(aws_session, ec2_client, ec2, get_instance_module, get_certificate):
    ssh_username = "ec2-user"
    instance = get_instance_module
    ssh_host = instance["PublicIpAddress"]
    cert_path = get_certificate
    db_credentials = get_database_credentials(aws_session)
    logging.info("Setting up SSH tunnel and MySQL connection")
    with SSHTunnelForwarder(
        (ssh_host, 22),
        ssh_username=ssh_username,
        ssh_pkey=cert_path,
        remote_bind_address=(db_credentials["host"], db_credentials["port"]),
    ) as tunnel:
        conn = pymysql.connect(
            host="127.0.0.1",
            user=db_credentials["username"],
            passwd=db_credentials["password"],
            db=db_credentials["dbname"],
            port=tunnel.local_bind_port,
        )
        yield conn  # Provide the fixture value
        logging.info("Closing MySQL connection")
        conn.close()


def get_db_secret_name(session):
    client = session.client(service_name="secretsmanager")
    paginator = client.get_paginator("list_secrets")
    page_iterator = paginator.paginate()
    secrets = []
    try:
        for page in page_iterator:
            secrets.extend(page["SecretList"])
        for secret in secrets:
            if "DatabaseDBSecret" in secret["Name"]:
                return secret["Name"]
    except Exception as e:
        logging.error(f"Error retrieving secrets: {e}")
        return None

    return secrets


def get_database_credentials(session):
    secret_name = get_db_secret_name(session)
    client = session.client(service_name="secretsmanager")

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
            secret_dict = json.loads(secret)
            return secret_dict
        else:
            raise Exception("Secret binary is not supported by this script.")

    except Exception as e:
        logging.error(f"Error retrieving secret: {e}")
        return None


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
        response = requests.post(
            _base_url + "/image", headers=base_headers, files=files
        )
        _id = response.json().get("id")
        uploaded_date = datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M")
    return _id, uploaded_date


def get_table_name(db):
    with db.cursor() as cursor:
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        return tables[0][0]


# new
def describe_dynamodb_table(dynamodb_client, table_name):
    response = dynamodb_client.describe_table(TableName=table_name)
    table = response["Table"]
    return table


def get_dynamodb_table_name(dynamodb_client):
    response = dynamodb_client.list_tables()
    table = response["TableNames"][0]
    return table


def check_ttl_status(dynamodb_client, table_name):
    response = dynamodb_client.describe_time_to_live(TableName=table_name)
    return response["TimeToLiveDescription"]["TimeToLiveStatus"]


def get_dynamodb_table_tags(dynamodb_client, table_arn):
    response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
    return response.get("Tags", [])


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


def get_lambda_configuration(lambda_client, function_name):
    response = lambda_client.get_function_configuration(FunctionName=function_name)
    return response


def get_lambda_tags(lambda_client, function_arn):
    response = lambda_client.list_tags(Resource=function_arn)
    return response["Tags"]


def list_lambda_triggers(lambda_client, function_name):
    response = lambda_client.list_event_source_mappings(FunctionName=function_name)
    return response["EventSourceMappings"]


def get_allowed_actions_by_role_and_permission(iam, part_role_name, part_policy_name):
    roles = iam.list_roles()
    list_roles(iam)
    for role in roles["Roles"]:
        if part_role_name in role["RoleName"].lower():
            attached_policies = iam.list_attached_role_policies(
                RoleName=role["RoleName"]
            )
            inline_policies = iam.list_role_policies(RoleName=role["RoleName"])
            if "AttachedPolicies" in attached_policies:
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
                        policy_action = []
                        for statement in document["Statement"]:
                            if statement["Effect"] == "Allow":
                                if isinstance(statement["Action"], str):
                                    policy_action.append(statement["Action"])
                                elif isinstance(statement["Action"], list):
                                    policy_action.extend(statement["Action"])
                        return policy_action

            if "PolicyNames" in inline_policies:
                for policy_name in inline_policies["PolicyNames"]:
                    if part_policy_name in policy_name:
                        policy_document = iam.get_role_policy(
                            RoleName=role["RoleName"], PolicyName=policy_name
                        )["PolicyDocument"]
                        policy_action = []
                        for statement in policy_document["Statement"]:
                            if statement["Effect"] == "Allow":
                                if isinstance(statement["Action"], str):
                                    policy_action.append(statement["Action"])
                                elif isinstance(statement["Action"], list):
                                    policy_action.extend(statement["Action"])
                        return policy_action


def list_roles(iam_client):
    """List all IAM roles and their associated policies."""
    try:
        # Paginator to handle the retrieval of all roles
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                print(f"Role Name: {role['RoleName']}")
                print("Attached Policies:")
                list_attached_policies(iam_client, role["RoleName"])
                print("Inline Policies:")
                list_inline_policies(iam_client, role["RoleName"])
                print("\n")
    except Exception as e:
        print(f"Error retrieving roles: {str(e)}")


def list_attached_policies(iam_client, role_name):
    """List attached policies for a given role."""
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page["AttachedPolicies"]:
                print(
                    f"  Policy Name: {policy['PolicyName']} (ARN: {policy['PolicyArn']})"
                )
    except Exception as e:
        print(f"Error retrieving attached policies for role {role_name}: {str(e)}")


def list_inline_policies(iam_client, role_name):
    """List inline policies for a given role."""
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page["PolicyNames"]:
                print(f"  Policy Name: {policy_name}")
    except Exception as e:
        print(f"Error retrieving inline policies for role {role_name}: {str(e)}")


# def check_lambda_sqs_subscription(lambda_client, lambda_function_name):
#     response = lambda_client.list_event_source_mappings(FunctionName=lambda_function_name)
#     for mapping in response['EventSourceMappings']:
#         source_arn = mapping['EventSourceArn']
#         if "sqs" in source_arn:
#             return True


def check_lambda_sqs_subscription(
    lambda_client, lambda_function_name, expected_sqs_arn
):
    response = lambda_client.list_event_source_mappings(
        FunctionName=lambda_function_name
    )
    for mapping in response["EventSourceMappings"]:
        if mapping["EventSourceArn"] == expected_sqs_arn:
            logging.info(
                f"Lambda function '{lambda_function_name}'"
                f" is correctly subscribed to SQS queue: {expected_sqs_arn}"
            )
            return True
    return False


@pytest.fixture(scope="module")
def sqs_client(aws_session):
    return aws_session.client("sqs")


def send_test_message_to_sqs(sqs_client, queue_url, message_body):
    response = sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_body)
    return response["MessageId"]
