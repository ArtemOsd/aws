import pytest_check as check

cxqa_iam_01_exp_data = {
    "FullAccessPolicyEC2": {
        "Policy": "FullAccessPolicyEC2",
        "Actions Allowed": ["ec2:*"],
        "Resources": "All",
        "Effect": "Allow",
    },
    "FullAccessPolicyS3": {
        "Policy": "FullAccessPolicyS3",
        "Actions Allowed": ["s3:*"],
        "Resources": "All",
        "Effect": "Allow",
    },
    "ReadAccessPolicyS3": {
        "Policy": "ReadAccessPolicyS3",
        "Actions Allowed": ["s3:Describe*", "s3:Get*", "s3:List*"],
        "Resources": "All",
        "Effect": "Allow",
    },
}


def test_policies(iam_client):
    response = iam_client.list_policies(Scope="Local")
    for policy in response["Policies"]:
        expected_data = cxqa_iam_01_exp_data[policy["PolicyName"]]
        expected_data["Actions Allowed"].sort()
        policy_response = iam_client.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )
        policy_settings = policy_response["PolicyVersion"]["Document"]["Statement"][0]
        policy_settings["Resource"] = (
            "All" if policy_settings["Resource"] == "*" else policy_settings["Resource"]
        )

        check.is_in(
            policy["PolicyName"],
            cxqa_iam_01_exp_data,
            f'{policy["PolicyName"]} is not in expected data',
        )
        if isinstance(policy_settings["Action"], str):
            policy_settings["Action"] = [policy_settings["Action"]]
        policy_settings["Action"].sort()

        check.equal(
            expected_data["Actions Allowed"],
            policy_settings["Action"],
            f'Wrong actions allowed for {policy["PolicyName"]}',
        )

        check.equal(
            policy_settings["Resource"],
            expected_data["Resources"],
            f'Wrong added resources for {policy["PolicyName"]}',
        )

        check.equal(
            policy_settings["Effect"],
            expected_data["Effect"],
            f'Wrong action of policy for {policy["PolicyName"]}',
        )
