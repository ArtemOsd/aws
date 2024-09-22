import os
import sys

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)
import requests

from tasks.task7_sns_sqs.conftest import get_confirmation_link_from_email, list_messages


def test_cxqa_snssqs_04_subscribe_notification(_base_url, base_headers, mail_creds):
    email = os.getenv("EMAIL")
    url = _base_url + "/notification/" + email
    response = requests.post(url, headers=base_headers)
    assert response.status_code == 200
    assert response.json() == "Successfully subscribed."
    assert get_confirmation_link_from_email(mail_creds)


def test_cxqa_snssqs_05_confirm_subscription(browser, sns_client, mail_creds):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    url = get_confirmation_link_from_email(mail_creds, is_mark_as_read=True)
    page = browser.new_page()
    page.goto(url)
    topic_locator = page.locator("[id='progress'] code")
    confirmation_locator = page.locator("h1[id='status']")
    assert (
        confirmation_locator.is_visible()
    ), "The Confirmation subscription should be visible."
    assert confirmation_locator.text_content() == "Subscription confirmed!"
    assert topic_arn in topic_locator.text_content()


def test_cxqa_snssqs_06_07_images_events(
    upload_images_to_s3_with_http, delete_file_via_http, mail_creds
):
    q = "is:unread event_type: upload -in:chats"
    mail = list_messages(mail_creds, q)[0].split("\r\n")
    assert any(item == "event_type: upload" for item in mail)
    assert any("download_link: http://ec2-" in item for item in mail)
    assert any("object_size:" in item for item in mail)
    assert any("object_key:" in item for item in mail)
    assert any("object_type:" in item for item in mail)
    q = "is:unread event_type: delete -in:chats"
    mail = list_messages(mail_creds, q)[0].split("\r\n")
    assert any(item == "event_type: delete" for item in mail)
    assert any("object_size:" in item for item in mail)
    assert any("object_key:" in item for item in mail)
    assert any("object_type:" in item for item in mail)


def test_cxqa_snssqs_08_images_events(
    upload_images_to_s3_with_http, base_headers, mail_creds
):
    q = "is:unread event_type: upload -in:chats"
    mail = list_messages(mail_creds, q)[0].split("\r\n")
    for item in mail:
        if "download_link:" in item:
            link = item.split(" ")[1]
            response = requests.get(link, headers=base_headers)
            assert "filename" in response.headers["content-disposition"]
            assert "image/jpg" in response.headers["content-type"]
            assert response.status_code == 200


def test_cxqa_snssqs_09_unsubscribe_notification(_base_url, base_headers, mail_creds):
    email = os.getenv("EMAIL")
    url = _base_url + "/notification/" + email
    response = requests.delete(url, headers=base_headers)
    assert response.status_code == 200
    assert response.json() == "Successfully unsubscribed."


def test_cxqa_snssqs_10_notification_unsubscribe(
    upload_images_to_s3_with_http, delete_file_via_http, mail_creds
):
    q = "is:unread event_type: upload -in:chats"
    mail = list_messages(mail_creds, q)
    assert not mail
    q = "is:unread event_type: delete -in:chats"
    mail = list_messages(mail_creds, q)
    assert not mail


def test_cxqa_snssqs_11_view_all_subscriptions(_base_url, base_headers, sns_client):
    topic_arn = sns_client.list_topics()["Topics"][0]["TopicArn"]
    url = _base_url + "/notification"
    email = os.getenv("EMAIL")
    response = requests.get(url, headers=base_headers)
    assert response.status_code == 200
    for item in response.json():
        if item["Endpoint"] == email:
            assert item["Protocol"] == "email"
            assert topic_arn in item["SubscriptionArn"]
            assert topic_arn == item["Endpoint"]
