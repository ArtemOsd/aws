import os
import sys

import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task6_databases.conftest import (
    can_ec2_access_rds,
    is_rds_in_private_subnet,
)


def test_access_via_subnets(ec2_client, rds_client, get_instance, get_rds_instance):
    db_instance_id = get_rds_instance["DBInstanceIdentifier"]
    is_private = is_rds_in_private_subnet(ec2_client, rds_client, db_instance_id)
    assert is_private


def test_access_via_subnets2(ec2_client, rds_client, get_instance, get_rds_instance):
    subnet_id = get_instance["SubnetId"]
    response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
    app_subnet_cidr = response["Subnets"][0]["CidrBlock"]
    db_instance = get_rds_instance
    db_subnet_group = db_instance["DBSubnetGroup"]
    db_security_groups = db_instance["VpcSecurityGroups"]
    public_access = db_instance["PubliclyAccessible"]
    check.is_true(
        not public_access,
        "RDS instance is publicly accessible, which is a security risk.",
    )

    for subnet in db_subnet_group["Subnets"]:
        subnet_details = ec2_client.describe_subnets(
            SubnetIds=[subnet["SubnetIdentifier"]]
        )
        is_private = any(
            tag["Key"] == "Name" and "private" in tag["Value"].lower()
            for tag in subnet_details["Subnets"][0]["Tags"]
        )
        check.is_true(
            is_private, f"Subnet {subnet['SubnetIdentifier']} is not private."
        )

    for sg in db_security_groups:
        sg_id = sg["VpcSecurityGroupId"]
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])
        for rule in sg_details["SecurityGroups"][0]["IpPermissions"]:
            for ip_range in rule.get("IpRanges", []):
                check.equal(
                    ip_range["CidrIp"],
                    app_subnet_cidr,
                    f"Security Group {sg_id} has an incorrect rule allowing access from {ip_range['CidrIp']}",
                )


def test_access_via_sg(ec2_client, rds_client, get_instance):
    instance = get_instance
    response = rds_client.describe_db_instances()
    db_instance_id = response["DBInstances"][0]["DBInstanceIdentifier"]
    has_access = can_ec2_access_rds(
        ec2_client, instance["InstanceId"], rds_client, db_instance_id
    )
    assert has_access
