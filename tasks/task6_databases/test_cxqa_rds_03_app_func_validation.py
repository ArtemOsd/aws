import os

import requests

from tasks.task6_databases.conftest import get_table_name


def test_cxqa_rds_03_metadata(upload_file, db):
    file_id, uploaded_date = upload_file
    table_name = get_table_name(db)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "resources", "test.jpg")
    file_size = os.path.getsize(file_path)
    with db.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = '{file_id}'")
        data = cursor.fetchall()
        for _id, object_key, object_type, last_modified, object_size in data:
            last_modified = last_modified.strftime("%Y-%m-%d %H:%M")
            assert isinstance(_id, int)
            assert last_modified == uploaded_date
            assert "test.jpg" in object_key
            assert "binary/octet-stream" == object_type
            assert file_size == object_size


def test_cxqa_rds_04_get_metadata_via_http(upload_file, db, base_headers, base_url):
    file_id, uploaded_date = upload_file
    table_name = get_table_name(db)
    url = base_url + "/" + str(file_id)
    header = {"Accept": "image/*"}
    response = requests.get(url, headers=header)
    assert response.status_code == 200
    response_data = response.json()
    with db.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = '{file_id}'")
        data = cursor.fetchall()
        for _id, object_key, object_type, last_modified, object_size in data:
            last_modified = last_modified.strftime("%Y-%m-%dT%H:%M:%SZ")
            assert _id == response_data["id"]
            assert last_modified == response_data["last_modified"]
            assert object_key == response_data["object_key"]
            assert object_type == response_data["object_type"]
            assert object_size == response_data["object_size"]


def test_cxqa_rds_05_removed_metadata(upload_file, db, base_url, base_headers):
    file_id, uploaded_date = upload_file
    table_name = get_table_name(db)
    with db.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = '{file_id}'")
        data = cursor.fetchall()
        assert len(data) == 1
        for _id, object_key, _, _, _ in data:
            assert _id
            assert "test.jpg" in object_key

    response = requests.get(base_url, headers=base_headers)
    _id = response.json()[0]["id"]
    url = base_url + "/" + str(_id)
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 200
    assert response.text.strip() == '"Image is deleted"'
    with db.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = '{file_id}'")
        data = cursor.fetchall()
        assert len(data) == 0, "item is not deleted"


def test_cxqa_rds_05_removed_metadata(upload_file, db, base_url, base_headers):
    file_id, uploaded_date = upload_file
    table_name = get_table_name(db)

    with db.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = '{file_id}'")
        data = cursor.fetchall()
        assert len(data) == 1
        for _id, object_key, _, _, _ in data:
            assert _id
            assert "test.jpg" in object_key
    url = base_url + "/" + str(_id)
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 200
    assert response.text.strip() == '"Image is deleted"'
