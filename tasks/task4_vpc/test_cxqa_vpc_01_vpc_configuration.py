import pytest_check as check


def test_vpc(ec2_client):
    vpcs_response = ec2_client.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["false"]}]
    )
    non_default_vpcs = vpcs_response["Vpcs"]
    for vpc in non_default_vpcs:
        vpc_id = vpc["VpcId"]
        subnets_response = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        subnets = subnets_response["Subnets"]
        assert len(subnets) == 2
        public_subnets = [subnet for subnet in subnets if subnet["MapPublicIpOnLaunch"]]
        private_subnets = [
            subnet for subnet in subnets if not subnet["MapPublicIpOnLaunch"]
        ]
        assert (
            public_subnets and private_subnets
        ), "There are not public and private subnets"


def test_vpc_cidr_block(ec2_client):
    cidr_block = "10.0.0.0/16"
    vpcs_response = ec2_client.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["false"]}]
    )
    non_default_vpcs = vpcs_response["Vpcs"]
    for vpc in non_default_vpcs:
        check.equal(vpc["CidrBlock"], cidr_block)


def test_vpc_tags(ec2_client):
    tag_key = "cloudx"
    tag_value = "qa"
    vpcs_response = ec2_client.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["false"]}]
    )
    non_default_vpcs = vpcs_response["Vpcs"]
    for vpc in non_default_vpcs:
        check.is_true(
            any(
                tag["Key"] == tag_key and tag["Value"] == tag_value
                for tag in vpc["Tags"]
            )
        )
