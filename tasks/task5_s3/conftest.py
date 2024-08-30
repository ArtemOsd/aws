import logging
import os

import boto3
import pytest
from botocore.exceptions import ClientError
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
def iam_client(aws_session):
    return aws_session.client("iam")


@pytest.fixture(scope="module")
def s3_client(aws_session):
    return aws_session.client("s3")


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


@pytest.fixture
def get_instance(ec2_client):
    instance_info = ec2_client.describe_instances()
    all_instances = instance_info["Reservations"][0]["Instances"]
    assert len(all_instances) == 1
    instance = instance_info["Reservations"][0]["Instances"][0]
    return instance


@pytest.fixture
def base_url(get_instance):
    instance_address = get_instance["PublicIpAddress"]
    return f"http://{instance_address}/api/image"


@pytest.fixture
def base_headers():
    return {"Accept": "application/json"}


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


# TODO split logic into small peaces
def check_application_accessibility(ec2, instance_id):
    # Get instance information
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_info["Reservations"][0]["Instances"][0]

    # Check if the instance has a public IP address and DNS name
    public_ip = instance.get("PublicIpAddress", None)
    public_dns = instance.get("PublicDnsName", None)
    if not public_ip or not public_dns:
        return False, "Instance does not have a public IP address or DNS name."

    # Get the subnet of the instance
    subnet_id = instance["SubnetId"]

    # Describe route tables associated with the subnet
    route_tables = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )

    # Check for a route to an Internet Gateway
    internet_gateway_route = False
    for route_table in route_tables["RouteTables"]:
        for route in route_table["Routes"]:
            if (
                route.get("GatewayId", "").startswith("igw-")
                and route["DestinationCidrBlock"] == "0.0.0.0/0"
            ):
                internet_gateway_route = True
                break
        if internet_gateway_route:
            break

    if not internet_gateway_route:
        return False, "No route to Internet Gateway in the subnet's route table."

    # Check Security Groups for inbound HTTP access
    sg_ids = [sg["GroupId"] for sg in instance["SecurityGroups"]]
    sg_details = ec2.describe_security_groups(GroupIds=sg_ids)
    http_access = False
    for sg in sg_details["SecurityGroups"]:
        for permission in sg["IpPermissions"]:
            # Check for inbound rules that allow HTTP traffic (port 80)
            if permission["FromPort"] <= 80 <= permission["ToPort"]:
                for ip_range in permission["IpRanges"]:
                    if ip_range["CidrIp"] == "0.0.0.0/0":
                        http_access = True
                        break
        if http_access:
            break

    if not http_access:
        return (
            False,
            "Security Groups do not allow inbound HTTP traffic from the internet.",
        )

    return True, "Application is accessible via HTTP from the internet."


# TODO split logic into small peaces
def check_ssh_access(ec2, instance_id):
    # Get instance details
    instance_details = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_details["Reservations"][0]["Instances"][0]

    # Check if the instance has a public IP address
    if "PublicIpAddress" not in instance:
        return False, "Instance does not have a public IP address."

    # Check if the instance is associated with a key pair
    if "KeyName" not in instance:
        return False, "Instance is not associated with any key pair for SSH access."

    # Get the security group IDs
    security_group_ids = [sg["GroupId"] for sg in instance["SecurityGroups"]]

    # Describe security groups and check for SSH access
    security_groups = ec2.describe_security_groups(GroupIds=security_group_ids)
    ssh_access = False
    for sg in security_groups["SecurityGroups"]:
        for permission in sg["IpPermissions"]:
            # Check for inbound rules allowing SSH (port 22)
            if permission["FromPort"] <= 22 <= permission["ToPort"]:
                for ip_range in permission["IpRanges"]:
                    if (
                        ip_range["CidrIp"] == "0.0.0.0/0"
                    ):  # This allows SSH from any IP, consider restricting it
                        ssh_access = True
                        break
            if ssh_access:
                break
        if ssh_access:
            break

    if not ssh_access:
        return False, "Security groups do not allow SSH access."

    return True, "Instance is accessible via SSH."


def get_all_buckets(s3):
    all_buckets = []
    response = s3.list_buckets()
    for bucket in response["Buckets"]:
        all_buckets.append(bucket["Name"])
    return all_buckets


def get_bucket_name(s3):
    buckets = get_all_buckets(s3)
    for bucket_name in buckets:
        if "cloudximage-imagestorebucket" in bucket_name:
            return bucket_name


def get_bucket_tags(s3, bucket_name):
    try:
        response = s3.get_bucket_tagging(Bucket=bucket_name)
        tags = response["TagSet"]
        return tags
    except s3.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchTagSet":
            logging.error(f"No tags found for bucket '{bucket_name}'.")
        else:
            logging.error(f"Failed to retrieve tags for bucket '{bucket_name}': {e}")


def get_bucket_encryption(s3, bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response["ServerSideEncryptionConfiguration"]["Rules"]
        for rule in rules:
            return rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    except s3.exceptions.ClientError as e:
        if (
            e.response["Error"]["Code"]
            == "ServerSideEncryptionConfigurationNotFoundError"
        ):
            logging.error(f"No encryption found for bucket {bucket_name}.")
        else:
            logging.error(
                f"Error getting encryption status for bucket {bucket_name}: {e}"
            )


def check_bucket_versioning(s3, bucket_name):
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status", "Not Configured")
        if status in ["Suspended", "Not Configured"]:
            return "disabled"
        else:
            return status
    except Exception as e:
        logging.error(f"Failed to get versioning status for {bucket_name}: {e}")


def check_public_access_settings(s3, bucket_name) -> dict:
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        settings = response["PublicAccessBlockConfiguration"]
        return settings
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        logging.error(f"No public access block settings configured for {bucket_name}.")
    except Exception as e:
        logging.error(f"Failed to get public access settings for {bucket_name}: {e}")


def upload_image_to_s3(s3, file_name, bucket, object_name=None):
    if object_name is None:
        object_name = file_name + "1"
    try:
        s3.upload_file(file_name, bucket, object_name)
        logging.info(f"File uploaded successfully: {object_name}")
    except Exception as e:
        logging.error(f"Upload failed: {e}")


def check_file_exists_in_bucket(s3, bucket_name, object_name):
    try:
        s3.head_object(Bucket=bucket_name, Key=object_name)
        return True
    except ClientError as e:
        error_code = int(e.response["Error"]["Code"])
        if error_code == 404:
            return False
        else:
            raise


def download_file_from_s3(s3, bucket_name, object_name, file_name):
    try:
        s3.download_file(bucket_name, object_name, file_name)
        logging.info(f"File downloaded successfully: {file_name}")
    except Exception as e:
        logging.error(f"Failed to download file: {e}")


def check_local_file_exists(file_path):
    if os.path.isfile(file_path):
        logging.info(f"File exists: {file_path}")
        return True
    else:
        logging.info(f"File does not exist: {file_path}")
        return False


def list_files_in_bucket(s3, bucket_name, prefix=""):
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if "Contents" in response:
            result = []
            for item in response["Contents"]:
                result.append(item["Key"])
            return result
        else:
            logging.info("No files found.")
            return []
    except Exception as e:
        logging.error(f"Error accessing bucket {bucket_name}: {e}")


def delete_file_from_s3(s3, bucket_name, object_name):
    try:
        s3.delete_object(Bucket=bucket_name, Key=object_name)
        logging.info(f"File deleted successfully: {object_name}")
    except Exception as e:
        logging.error(f"Failed to delete file: {e}")


def get_allowed_actions_by_role_and_permission(iam, part_role_name, part_policy_name):
    roles = iam.list_roles()
    for role in roles["Roles"]:
        if part_role_name in role["RoleName"].lower():
            attached_policies = iam.list_attached_role_policies(
                RoleName=role["RoleName"]
            )
            for policy in attached_policies["AttachedPolicies"]:
                if part_policy_name in policy["PolicyName"].lower():
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


def validate_json(data, schema):
    import jsonschema
    from jsonschema import validate

    try:
        validate(instance=data, schema=schema)
        return True, "JSON data is valid."
    except jsonschema.exceptions.ValidationError as err:
        return False, str(err)


@pytest.fixture
def upload_test_file_to_bucket(s3_client):
    file_name = "resources/test.jpg"
    import time

    timestamp = str(int(time.time()))
    object_name = f"resources/test{timestamp}.jpg"
    bucket = get_bucket_name(s3_client)
    upload_image_to_s3(s3_client, file_name, bucket, object_name)
    return object_name
