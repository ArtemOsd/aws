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
def base_url(get_instance):
    instance_address = get_instance["PublicIpAddress"]
    return f"http://{instance_address}/api/image"


@pytest.fixture
def base_headers():
    return {"Accept": "application/json"}


@pytest.fixture()
def upload_file(base_url, base_headers):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "test.jpg")
    with open(file_path, "rb") as file:
        files = {"upfile": file}
        response = requests.post(base_url, headers=base_headers, files=files)
        _id = response.json().get("id")
        uploaded_date = datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M")
    return _id, uploaded_date


def get_table_name(db):
    with db.cursor() as cursor:
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        return tables[0][0]
