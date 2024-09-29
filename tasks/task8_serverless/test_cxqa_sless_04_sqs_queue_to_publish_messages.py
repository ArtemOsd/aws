import os
import sys


parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)

from tasks.task8_serverless.conftest import send_test_message, receive_test_message


def test_cxqa_sless_04_send_message(sqs_client):
    queue_url = sqs_client.list_queues()["QueueUrls"][0]
    response = send_test_message(sqs_client, queue_url)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert response.get("MessageId", None)
    assert response.get("MD5OfMessageBody", None)
    receive_response = receive_test_message(sqs_client, queue_url)
    assert receive_response["ResponseMetadata"]["HTTPStatusCode"] == 200
