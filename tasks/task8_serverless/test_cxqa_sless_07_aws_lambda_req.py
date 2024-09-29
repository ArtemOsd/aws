import os
import sys

import pytest_check as check

parent_folder = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)
sys.path.insert(0, parent_folder)


from tasks.task8_serverless.conftest import (
    get_lambda_configuration,
    get_lambda_tags,
    list_lambda_triggers,
)


def test_cxqa_sless_07_dynamodb_requirements(lambda_client):
    list_functions = lambda_client.list_functions()
    function_name = ""
    for function in list_functions["Functions"]:
        if "Lambda" in function["FunctionName"]:
            function_name = function["FunctionName"]
    config = get_lambda_configuration(lambda_client, function_name)
    check.equal(config["MemorySize"], 128)
    check.equal(config["EphemeralStorage"]["Size"], 512)
    check.equal(config["Timeout"], 3)
    tags = get_lambda_tags(lambda_client, config["FunctionArn"])
    check.is_true(any(tag == "cloudx" and value == "qa" for tag, value in tags.items()))
    triggers = list_lambda_triggers(lambda_client, function_name)
    check.is_true(
        any(
            "SQSQueue".lower() in trigger["EventSourceArn"].lower()
            for trigger in triggers
        )
    )
    log_group_name = f"/aws/lambda/{function_name}"
    check.is_in("aws/lambda/cloudxserverless-EventHandlerLambda", log_group_name)
