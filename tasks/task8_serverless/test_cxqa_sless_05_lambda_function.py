import os
import sys


parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)

from tasks.task8_serverless.conftest import (
    check_lambda_sqs_subscription,
    send_test_message_to_sqs,
)


def test_cxqa_sless_05_lambda_is_subscribed(lambda_client, sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    response = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )
    list_functions = lambda_client.list_functions()
    lambda_function_name = ""
    for function in list_functions["Functions"]:
        if "Lambda" in function["FunctionName"]:
            lambda_function_name = function["FunctionName"]
    assert check_lambda_sqs_subscription(
        lambda_client, lambda_function_name, response["Attributes"]["QueueArn"]
    )


def test_cxqa_sless_05_check_send_test_message_to_sqs(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    message_id = send_test_message_to_sqs(
        sqs_client, queue_url, "Hello, this is a test message!"
    )
    assert message_id
