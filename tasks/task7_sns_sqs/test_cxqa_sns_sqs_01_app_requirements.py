import os
import sys

import pytest_check as check
import requests

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
from tasks.task7_sns_sqs.conftest import (
    send_test_message,
    receive_test_message,
    get_allowed_actions_by_role_and_permission,
)


def test_list_subscriptions(
    subscribe_random_email, _base_url, base_headers, sns_client
):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    email = subscribe_random_email
    url = _base_url + "/notification"
    response = requests.get(url, headers=base_headers)
    subscriptions_list = response.json()
    assert any(item["Endpoint"] == email for item in subscriptions_list)
    for item in subscriptions_list:
        if item["Endpoint"] == email:
            check.equal(
                item["Protocol"], "email", msg=f"wrong protocol::{item['Protocol']}"
            )
            check.equal(
                item["SubscriptionArn"],
                "PendingConfirmation",
                msg=f"wrong SubscriptionArn::{item['SubscriptionArn']}",
            )
            check.equal(
                item["TopicArn"], topic_arn, msg=f"wrong TopicArn::{item['TopicArn']}"
            )


def test_subscribe_notification(_base_url, base_headers):
    email = os.getenv("EMAIL")
    url = _base_url + "/notification/" + email
    response = requests.post(url, headers=base_headers)
    assert response.status_code == 200
    assert response.json() == "Successfully subscribed email to SNS Topic"


def test_subscribe_notification_bad_email(_base_url, base_headers):
    email = "test"
    url = _base_url + "/notification/" + email
    response = requests.post(url, headers=base_headers)
    assert response.status_code == 400
    assert response.json() == "Invalid email address provided"


def test_unsubscribe_notification_w_o_confirmation(
    subscribe_random_email, _base_url, base_headers
):
    email = subscribe_random_email
    url = _base_url + "/notification/" + email
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 412
    assert response.json() == "Cannot unsubscribe, confirmation is still pending"


def test_unsubscribe_wrong_email(_base_url, base_headers):
    import time

    random_value = int(time.time())
    email = f"{random_value}@myunrealgmail.com"
    url = _base_url + "/notification/" + email
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 404
    assert response.json() == "Subscription is not found"


def test_queue_tags(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    response = send_test_message(sqs_client, queue_url)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert response.get("MessageId", None)
    assert response.get("MD5OfMessageBody", None)
    receive_response = receive_test_message(sqs_client, queue_url)
    assert receive_response["ResponseMetadata"]["HTTPStatusCode"] == 200


def test_access_to_sqs_and_sns_topic(iam_client):
    expected_publish_permission = ["sns:Publish"]
    expected_subscription_permission = [
        "sns:ListSubscriptions*",
        "sns:Subscribe",
        "sns:Unsubscribe",
    ]
    actual_permissions_publish = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudximage-app",
        part_policy_name="cloudximage-TopicPublish",
    )
    for permission in actual_permissions_publish:
        check.is_in(permission, expected_publish_permission)
    actual_subscription_permission = get_allowed_actions_by_role_and_permission(
        iam_client,
        part_role_name="cloudximage-app",
        part_policy_name="cloudximage-TopicSubscription",
    )
    for permission in actual_subscription_permission:
        check.is_in(permission, expected_subscription_permission)
