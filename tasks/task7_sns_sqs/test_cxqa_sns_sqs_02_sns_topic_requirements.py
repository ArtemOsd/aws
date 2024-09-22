import os
import sys

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task7_sns_sqs.conftest import (
    get_topic_type,
    get_topic_tags,
    check_sns_encryption_status,
)


def test_topic_name(sns_client):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    topic_name = topic_arn.split(":")[-1]
    assert "cloudximage-TopicSNSTopic" in topic_name


def test_topic_type(sns_client):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    topic_type = get_topic_type(sns_client, topic_arn)
    assert topic_type.lower() == "standard"


def test_topic_encryption(sns_client):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    encryption_status = check_sns_encryption_status(sns_client, topic_arn)
    assert encryption_status == "disabled"


def test_topic_tags(sns_client):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    tags = get_topic_tags(sns_client, topic_arn)
    assert any(tag["Key"] == "cloudx" and tag["Value"] == "qa" for tag in tags)
