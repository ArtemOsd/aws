import os
import sys
from time import sleep

import requests
import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task6_databases.conftest import (
    get_table_name,
    get_dynamodb_table_name,
    dynamodb_table_data,
)


def test_cxqa_rds_03_metadata(upload_file, dynamodb_client, dynamodb_resource):
    file_id, uploaded_date, file_name, file_size = upload_file
    table_data = dynamodb_table_data(dynamodb_client, dynamodb_resource)
    for item in table_data["Items"]:
        if item["id"] != file_id:
            continue
        else:
            check.equal(item["id"], file_id)
            check.equal(int(item["last_modified"]), uploaded_date)
            check.is_in(file_name, item["object_key"])
            check.equal(item["object_type"], "binary/octet-stream")
            assert item["object_type"] == "binary/octet-stream"
            assert item["object_size"] == file_size
            break


def test_cxqa_rds_04_get_metadata_via_http(
    upload_file, dynamodb_client, dynamodb_resource, base_headers, _base_url
):
    file_id, uploaded_date, file_name, file_size = upload_file
    url = _base_url + "/" + str(file_id)
    header = {"Accept": "image/*"}
    response = requests.get(url, headers=header)
    assert response.status_code == 200
    response_data = response.json()
    table_data = dynamodb_table_data(dynamodb_client, dynamodb_resource)
    for item in table_data["Items"]:
        if item["id"] != file_id:
            continue
        else:
            check.equal(item["id"], file_id)
            check.equal(int(item["last_modified"]), response_data["last_modified"])
            check.equal(item["object_key"], response_data["object_key"])
            check.equal(item["object_type"], response_data["object_type"])
            check.equal(item["object_size"], response_data["object_size"])
            break


def test_cxqa_rds_05_removed_metadata(
    upload_file, dynamodb_client, dynamodb_resource, _base_url, base_headers
):
    file_id, uploaded_date, file_name, file_size = upload_file
    table_data = dynamodb_table_data(dynamodb_client, dynamodb_resource)
    assert any(item["id"] == file_id for item in table_data["Items"])
    url = _base_url + "/" + str(file_id)
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 200
    assert response.text.strip() == '"Image is deleted"'
    table_data = dynamodb_table_data(dynamodb_client, dynamodb_resource)
    assert not any(
        item["id"] == file_id for item in table_data["Items"]
    ), "item is not deleted"
