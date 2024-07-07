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
        policy_response = iam_client.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )
        policy_settings = policy_response["PolicyVersion"]["Document"]["Statement"][0]
        policy_settings["Resource"] = (
            "All" if policy_settings["Resource"] == "*" else policy_settings["Resource"]
        )
        assert policy["PolicyName"] in cxqa_iam_01_exp_data
        expected_data = cxqa_iam_01_exp_data[policy["PolicyName"]]
        expected_data["Actions Allowed"].sort()
        if isinstance(policy_settings["Action"], str):
            policy_settings["Action"] = [policy_settings["Action"]]
        policy_settings["Action"].sort()
        assert expected_data["Actions Allowed"] == policy_settings["Action"]
        assert policy_settings["Resource"] == expected_data["Resources"]
        assert policy_settings["Effect"] == expected_data["Effect"]
