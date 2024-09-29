import os
import sys

import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)


from tasks.task8_serverless.conftest import get_allowed_actions_by_role_and_permission


def test_access_to_s3_bucket(iam_client):
    image_store_bucket_policy = [
        "s3:ListBucket",
        "s3:DeleteObject*",
        "s3:GetObject*",
        "s3:PutObject*",
    ]
    app_instance_appsource_bucket_policy = ["s3:ListBucket", "s3:GetObject*"]

    actual_permissions_publish = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudxserverless-app",
        part_policy_name="ImageStoreBucketPolicy",
    )
    for permission in actual_permissions_publish:
        check.is_in(permission, image_store_bucket_policy)
    actual_permissions_publish = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudxserverless-app",
        part_policy_name="AppInstanceAppSourceBucketPolicy",
    )
    for permission in actual_permissions_publish:
        check.is_in(permission, app_instance_appsource_bucket_policy)


def test_access_to_dynamodb(iam_client):
    dynamodb_permissions = [
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:ConditionCheckItem",
        "dynamodb:DeleteItem",
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:UpdateItem",
    ]

    actual_permissions_publish = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudxserverless-app",
        part_policy_name="AppInstanceInstanceRoleDefaultPolicy",
    )
    for permission in dynamodb_permissions:
        check.is_in(permission, actual_permissions_publish)


def test_access_to_sqs(iam_client):
    sqs_permissions = ["sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:SendMessage"]
    actual_permissions_publish = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudxserverless-app",
        part_policy_name="AppInstanceInstanceRoleDefaultPolicy",
    )
    for permission in sqs_permissions:
        check.is_in(permission, actual_permissions_publish)


def test_access_to_sns(iam_client):
    sns_permissions = ["sns:ListSubscriptions*", "sns:Subscribe", "sns:Unsubscribe"]
    actual_permissions_publish = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudxserverless-app",
        part_policy_name="TopicSubscriptionPolicy",
    )
    for permission in actual_permissions_publish:
        check.is_in(permission, sns_permissions)
