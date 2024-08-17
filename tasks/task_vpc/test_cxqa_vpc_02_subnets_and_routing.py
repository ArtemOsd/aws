import os
import sys

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task_vpc.conftest import (
    check_internet_gateway_access,
    check_instance_access,
    check_nat_gateway_access,
    check_instance_accessibility,
)


def test_public_instance_accessible_from_internet(instances, ec2_client):
    public_id = instances["public"]["InstanceId"]
    is_accessible, message = check_internet_gateway_access(ec2_client, public_id)
    assert is_accessible, message


def test_private_instance_has_no_accessible_from_internet(instances, ec2_client):
    public_id = instances["private"]["InstanceId"]
    is_accessible, message = check_internet_gateway_access(ec2_client, public_id)
    assert not is_accessible, message


def test_access_from_public_to_private(ec2_client, instances):
    public_id = instances["public"]["InstanceId"]
    private_id = instances["private"]["InstanceId"]
    has_access, message = check_instance_access(ec2_client, public_id, private_id)
    assert has_access, message


def test_private_have_access_via_nat_gateway(ec2_client, instances):
    private_id = instances["private"]["InstanceId"]
    has_access, message = check_nat_gateway_access(ec2_client, private_id)
    assert has_access, message


def test_private_has_not_access_from_public_internet(ec2_client, instances):
    private_id = instances["private"]["InstanceId"]
    has_access, message = check_instance_accessibility(ec2_client, private_id)
    assert has_access, message
