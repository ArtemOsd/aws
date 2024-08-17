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


def check_internet_gateway_access(ec2, instance_id):
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_info["Reservations"][0]["Instances"][0]

    if "PublicIpAddress" not in instance:
        return False, "Instance does not have a public IP address."

    subnet_id = instance["SubnetId"]
    route_tables = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )

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

    sg_ids = [sg["GroupId"] for sg in instance["SecurityGroups"]]
    sg_details = ec2.describe_security_groups(GroupIds=sg_ids)
    for sg in sg_details["SecurityGroups"]:
        for permission in sg["IpPermissions"]:
            for ip_range in permission["IpRanges"]:
                if ip_range["CidrIp"] == "0.0.0.0/0":
                    return (
                        True,
                        "Instance is accessible from the internet via an Internet Gateway.",
                    )

    return False, "Security Groups do not allow inbound traffic from the internet."


def check_security_group_access(ec2, src_instance_id, dest_instance_id):
    instances_info = ec2.describe_instances(
        InstanceIds=[src_instance_id, dest_instance_id]
    )
    src_instance = instances_info["Reservations"][0]["Instances"][0]
    dest_instance = instances_info["Reservations"][1]["Instances"][0]

    src_sg_ids = [sg["GroupId"] for sg in src_instance["SecurityGroups"]]
    dest_sg_ids = [sg["GroupId"] for sg in dest_instance["SecurityGroups"]]

    src_sg_details = ec2.describe_security_groups(GroupIds=src_sg_ids)
    for sg in src_sg_details["SecurityGroups"]:
        for permission in sg["IpPermissionsEgress"]:
            for ip_range in permission.get("UserIdGroupPairs", []):
                if ip_range["GroupId"] in dest_sg_ids:
                    return True
    return False


def check_instance_access(ec2, public_instance_id, private_instance_id):
    instances_info = ec2.describe_instances(
        InstanceIds=[public_instance_id, private_instance_id]
    )
    public_instance = instances_info["Reservations"][0]["Instances"][0]
    private_instance = instances_info["Reservations"][1]["Instances"][0]

    public_sg_ids = [sg["GroupId"] for sg in public_instance["SecurityGroups"]]
    private_sg_ids = [sg["GroupId"] for sg in private_instance["SecurityGroups"]]

    sg_details = ec2.describe_security_groups(GroupIds=public_sg_ids)
    for sg in sg_details["SecurityGroups"]:
        for permission in sg["IpPermissions"]:
            for ip_range in permission.get("UserIdGroupPairs", []):
                if ip_range["GroupId"] in private_sg_ids:
                    return (
                        True,
                        "Public instance has access to the private instance via Security Groups.",
                    )

    if public_instance["VpcId"] != private_instance["VpcId"]:
        return False, "Instances are not in the same VPC."

    public_subnet_id = public_instance["SubnetId"]
    private_subnet_id = private_instance["SubnetId"]
    acl_details = ec2.describe_network_acls(
        Filters=[
            {
                "Name": "association.subnet-id",
                "Values": [public_subnet_id, private_subnet_id],
            }
        ]
    )
    for acl in acl_details["NetworkAcls"]:
        for entry in acl["Entries"]:
            if entry["Egress"] and entry["RuleAction"] == "allow":
                return (
                    True,
                    "Network ACLs allow traffic from the public to the private instance.",
                )

    return False, "No sufficient permissions found in Security Groups or Network ACLs."


def check_nat_gateway_access(ec2, instance_id):
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_info["Reservations"][0]["Instances"][0]

    subnet_id = instance["SubnetId"]

    route_tables = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )

    nat_gateway_route = False
    for route_table in route_tables["RouteTables"]:
        logging.info(route_table)
        for route in route_table["Routes"]:
            if "NatGatewayId" in route:
                nat_gateway_route = True
                break
        if nat_gateway_route:
            break

    if not nat_gateway_route:
        return False, "No route to NAT Gateway in the subnet's route table."

    return True, "Private instance has access to the internet via NAT Gateway."


def check_instance_accessibility(ec2, instance_id):
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_info["Reservations"][0]["Instances"][0]

    has_public_ip = "PublicIpAddress" in instance and instance["PublicIpAddress"] != ""
    has_public_dns = "PublicDnsName" in instance and instance["PublicDnsName"] != ""

    if not has_public_ip and not has_public_dns:
        return (
            True,
            "Instance does not have a public IP or DNS, and is not accessible from the internet.",
        )

    sg_ids = [sg["GroupId"] for sg in instance["SecurityGroups"]]

    sg_details = ec2.describe_security_groups(GroupIds=sg_ids)
    for sg in sg_details["SecurityGroups"]:
        logging.info(sg)
        for permission in sg["IpPermissions"]:
            for ip_range in permission["IpRanges"]:
                if ip_range["CidrIp"] == "0.0.0.0/0":
                    return (
                        False,
                        "Security Group has a rule that allows access from the internet.",
                    )

    subnet_id = instance["SubnetId"]

    acl_details = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )
    for acl in acl_details["NetworkAcls"]:
        logging.info(acl)
        for entry in acl["Entries"]:
            if not entry["Egress"] and entry["RuleAction"] == "allow":
                for cidr in entry["CidrBlock"]:
                    if cidr == "0.0.0.0/0":
                        return (
                            False,
                            "Network ACL allows inbound traffic from the internet.",
                        )
    return True, "Private instance is not accessible from the public internet."
