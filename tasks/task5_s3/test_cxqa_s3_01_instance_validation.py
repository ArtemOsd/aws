import logging
import os
import sys

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task5_s3.conftest import (
    check_application_accessibility,
    check_ssh_access,
    get_allowed_actions_by_role_and_permission,
)


def test_app_accessible_from_internet(ec2_client, get_instance):
    """The application is deployed in the public subnet and should be accessible
    by HTTP from the internet via an Internet gateway by public IP address and FQDN."""
    instance = get_instance
    is_accessible, message = check_application_accessibility(
        ec2_client, instance["InstanceId"]
    )
    logging.info(message)
    assert is_accessible, message


def test_app_accessible_by_ssh(ec2_client, get_instance):
    """The application instance should be accessible by SSH protocol."""
    instance = get_instance
    is_accessible, message = check_ssh_access(ec2_client, instance["InstanceId"])
    logging.info(message)
    assert is_accessible, message


def test_app_has_access_to_s3_via_iam_role(iam_client, s3_client):
    """The application instance should be accessible by SSH protocol."""
    expected_permissions = [
        "s3:ListBucket",
        "s3:DeleteObject*",
        "s3:GetObject*",
        "s3:PutObject*",
    ]
    actual_permissions = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudximage-app",
        part_policy_name="cloudximage-imagestorebucket",
    )
    assert expected_permissions == actual_permissions
