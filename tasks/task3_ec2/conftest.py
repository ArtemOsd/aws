import logging
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
def ec2_client(aws_session):
    return aws_session.client("ec2")


@pytest.fixture(scope="module")
def ec2(aws_session):
    return aws_session.resource("ec2")


@pytest.fixture
def instances(ec2_client):
    instances_data = {"public": None, "private": None}
    response = ec2_client.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            for sg in instance["SecurityGroups"]:
                sg_response = ec2_client.describe_security_groups(
                    GroupIds=[sg["GroupId"]]
                )
                for permission in sg_response["SecurityGroups"][0]["IpPermissions"]:
                    if any(
                        ip_range["CidrIp"] == "0.0.0.0/0"
                        for ip_range in permission.get("IpRanges")
                    ):
                        instances_data["public"] = instance
                    else:
                        instances_data["private"] = instance
    return instances_data


@pytest.fixture()
def forward_80_port_via_ssh(instances, get_certificate):
    cert_path = get_certificate
    remote_user = "ec2-user"
    local_host = "127.0.0.1"
    local_port = 10022
    public_inst_port = 22
    private_inst_port = 80
    private_instance_ip = instances["private"]["PrivateIpAddress"]
    public_instance_ip = instances["public"]["PublicIpAddress"]
    from sshtunnel import SSHTunnelForwarder

    server = SSHTunnelForwarder(
        (public_instance_ip, public_inst_port),
        ssh_username=remote_user,
        ssh_pkey=cert_path,
        remote_bind_address=(private_instance_ip, private_inst_port),
        local_bind_address=(local_host, local_port),
    )
    logging.info("server connected")
    server.start()
    yield local_host, local_port
    server.stop()


@pytest.fixture()
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
