import os
import sys
import time
import pytest_check as check

import requests

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task5_s3.conftest import (
    get_bucket_name,
    upload_image_to_s3,
    download_file_from_s3,
    list_files_in_bucket,
    check_file_exists_in_bucket,
    check_local_file_exists,
    delete_file_from_s3,
    validate_json,
)


def test_upload_images_to_s3_with_boto(ec2_client, s3_client):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "test.jpg")
    timestamp = str(int(time.time()))
    object_name = f"resources/test{timestamp}.jpg"
    bucket = get_bucket_name(s3_client)
    upload_image_to_s3(s3_client, file_path, bucket, object_name)
    is_uploaded = check_file_exists_in_bucket(s3_client, bucket, object_name)
    assert is_uploaded


def test_upload_images_to_s3_with_http(_base_url, base_headers):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "test.jpg")
    with open(file_path, "rb") as file:
        files = {"upfile": file}
        response = requests.post(_base_url, headers=base_headers, files=files)
        check.is_true(response.status_code == 200)
        check.is_true(response.headers["content-type"] == "application/json")
        check.is_true("id" in response.json())
        check.is_true(response.json().get("id", None))


def test_download_images_to_s3(ec2_client, s3_client):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "1.jpg")
    bucket_name = get_bucket_name(s3_client)
    files = list_files_in_bucket(s3_client, bucket_name, "")
    download_file_from_s3(s3_client, bucket_name, files[0], file_path)
    is_download = check_local_file_exists(file_path)
    assert is_download
    os.unlink(file_path)


def test_download_images_to_s3_via_http(_base_url, base_headers):
    response = requests.get(_base_url, headers=base_headers)
    _id = response.json()[0]["id"]
    url = _base_url + "/file/" + str(_id)
    header = {"Accept": "image/png"}
    response = requests.get(url, headers=header)
    assert "filename" in response.headers["content-disposition"]
    assert "image/png" in response.headers["content-type"]
    assert response.status_code == 200


def test_view_list_uploaded_to_s3(ec2_client, s3_client):
    bucket_name = get_bucket_name(s3_client)
    list_files_in_bucket(bucket_name, "")


def test_view_list_to_s3_via_http(_base_url, base_headers):
    response = requests.get(_base_url, headers=base_headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    for item in response.json():
        check.is_true(isinstance(item["id"], int))
        check.is_true(isinstance(item["last_modified"], str))
        check.is_true(isinstance(item["object_key"], str))
        check.is_true(isinstance(item["object_size"], int))
        check.is_true(isinstance(item["object_type"], str))


def test_delete_file(ec2_client, s3_client, upload_test_file_to_bucket):
    object_name = upload_test_file_to_bucket
    bucket_name = get_bucket_name(s3_client)
    delete_file_from_s3(s3_client, bucket_name, object_name)
    files = list_files_in_bucket(s3_client, bucket_name, "")
    assert object_name not in files


def test_delete_file_via_http(_base_url, base_headers):
    response = requests.get(_base_url, headers=base_headers)
    _id = response.json()[0]["id"]
    url = _base_url + "/" + str(_id)
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.text.strip() == '"Image is deleted"'
