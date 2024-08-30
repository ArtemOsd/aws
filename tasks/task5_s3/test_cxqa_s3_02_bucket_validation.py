import os
import sys

import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task5_s3.conftest import (
    get_all_buckets,
    get_bucket_name,
    get_bucket_tags,
    get_bucket_encryption,
    check_bucket_versioning,
    check_public_access_settings,
)


def test_buckets_name(ec2_client, s3_client):
    buckets = get_all_buckets(s3_client)
    assert any("cloudximage-imagestorebucket" in bucket_name for bucket_name in buckets)


def test_buckets_tags(ec2_client, s3_client):
    bucket = get_bucket_name(s3_client)
    tags = get_bucket_tags(s3_client, bucket)
    cloudx_tag = None
    for tag in tags:
        if tag["Key"] == "cloudx":
            cloudx_tag = tag
    assert f"{cloudx_tag['Key']}: {cloudx_tag['Value']}" == "cloudx: qa"


def test_bucket_encryption(ec2_client, s3_client):
    bucket = get_bucket_name(s3_client)
    encryption = get_bucket_encryption(s3_client, bucket)
    assert encryption == "AES256"


def test_buckets_versioning(ec2_client, s3_client):
    bucket = get_bucket_name(s3_client)
    status = check_bucket_versioning(s3_client, bucket)
    assert status == "disabled"


def test_bucket_public_access(ec2_client, s3_client):
    bucket = get_bucket_name(s3_client)
    settings = check_public_access_settings(s3_client, bucket)
    for setting, value in settings.items():
        check.is_true(value, f"{setting} is disabled")
