import requests
import os
import sys

import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)


def test_cxqa_serverless_02_get_metadata_via_http(
    upload_file, base_headers, _base_url, dynamodb_client, dynamodb_resource
):
    file_id, uploaded_date = upload_file
    url = _base_url + "/image/" + str(file_id)
    header = {"Accept": "image/*"}
    response = requests.get(url, headers=header)
    assert response.status_code == 200
    upload_response_data = response.json()
    response = dynamodb_client.list_tables()
    table_names = response.get("TableNames", [])
    assert table_names
    table_name = table_names[0]
    table = dynamodb_resource.Table(table_name)
    table_data = table.scan()
    for item in table_data["Items"]:
        if item["id"] != upload_response_data["id"]:
            continue
        else:
            assert item["id"] == upload_response_data["id"]
            assert int(item["last_modified"]) == upload_response_data["last_modified"]
            assert item["object_key"] == upload_response_data["object_key"]
            assert item["object_type"] == upload_response_data["object_type"]
            assert item["object_size"] == upload_response_data["object_size"]
            break
