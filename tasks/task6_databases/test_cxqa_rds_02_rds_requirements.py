import os
import sys

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task6_databases.conftest import get_rds_instance_type


def test_instance_type(rds_client, get_rds_instance):
    db_instance_id = get_rds_instance["DBInstanceIdentifier"]
    instance_type = get_rds_instance_type(rds_client, db_instance_id)
    assert instance_type == "db.t3.micro"


def test_multi_az(get_rds_instance):
    multi_az = get_rds_instance["MultiAZ"]
    assert not multi_az


def test_storage_size(get_rds_instance):
    storage_size = get_rds_instance["AllocatedStorage"]
    storage_size_str = f"{str(storage_size)} GiB"
    assert storage_size_str == "100 GiB"


def test_storage_type(get_rds_instance):
    storage_size = get_rds_instance["StorageType"]
    assert storage_size == "gp2"


def test_encryption(get_rds_instance):
    encryption_status = get_rds_instance["StorageEncrypted"]
    actual_result = "enabled" if encryption_status else "not enabled"
    assert actual_result == "not enabled"


def test_tags(get_rds_instance):
    tags = get_rds_instance["TagList"]
    assert any(tag["Key"] == "cloudx" and tag["Value"] == "qa" for tag in tags)


def test_database_type(get_rds_instance):
    engine_type = get_rds_instance["Engine"]
    assert engine_type == "mysql"


def test_database_version(get_rds_instance):
    engine_version = get_rds_instance["EngineVersion"]
    assert engine_version == "8.0.32"
