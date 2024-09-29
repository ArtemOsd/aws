import os
import sys

import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)

from tasks.task8_serverless.conftest import (
    describe_dynamodb_table,
    get_dynamodb_table_name,
    check_ttl_status,
    get_dynamodb_table_tags,
)


def test_cxqa_sless_01_dynamodb_requirements(dynamodb_client):
    table_name = get_dynamodb_table_name(dynamodb_client)
    table_info = describe_dynamodb_table(dynamodb_client, table_name)

    check.is_in("loudxserverless-DatabaseImagesTable", table_info["TableName"])
    provisioned_read_capacity = table_info.get("ProvisionedThroughput", {}).get(
        "ReadCapacityUnits"
    )
    check.is_true(provisioned_read_capacity == 5)
    provisioned_write_capacity = table_info.get("ProvisionedThroughput", {}).get(
        "WriteCapacityUnits"
    )
    check.is_true(1 <= provisioned_write_capacity <= 5)

    ttl_status = check_ttl_status(dynamodb_client, table_name)

    check.equal(ttl_status.lower(), "disabled")
    table_arn = table_info["TableArn"]
    tags = get_dynamodb_table_tags(dynamodb_client, table_arn)
    assert any(tag["Key"] == "cloudx" and tag["Value"] == "qa" for tag in tags)
