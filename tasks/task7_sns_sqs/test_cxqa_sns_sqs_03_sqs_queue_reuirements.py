import os
import sys

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task7_sns_sqs.conftest import (
    check_sqs_encryption_status,
    get_queue_type,
    get_queue_tags,
    check_dlq_settings,
)


def test_queue_name(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    queue_name = queue_url.split("/")[-1]
    assert "cloudximage-QueueSQSQueue" in queue_name


def test_queue_encryption(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    encryption_status = check_sqs_encryption_status(sqs_client, queue_url)
    assert encryption_status == "enabled"


def test_queue_type(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    queue_type = get_queue_type(queue_url)
    assert queue_type.lower() == "standard"


def test_queue_tags(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    tags = get_queue_tags(sqs_client, queue_url)
    assert any(key == "cloudx" and value == "qa" for key, value in tags.items())


def test_dead_letter_tags(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    dead_letter = check_dlq_settings(sqs_client, queue_url)
    assert dead_letter == "no"
