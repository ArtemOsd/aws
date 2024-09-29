import os
import sys


parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)

import requests

from tasks.task8_serverless.conftest import get_confirmation_link_from_email


def test_cxqa_sless_03_send_message(_base_url, base_headers, mail_creds):
    email = os.getenv("EMAIL")
    url = _base_url + "/notification/" + email
    response = requests.post(url, headers=base_headers)
    assert response.status_code == 200
    assert response.json() == "Successfully subscribed email to SNS Topic"
    assert get_confirmation_link_from_email(mail_creds)
