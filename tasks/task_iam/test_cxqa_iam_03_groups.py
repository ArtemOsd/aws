cxqa_iam_03_exp_data = {
    "FullAccessGroupEC2": {
        "Group": "FullAccessGroupEC2",
        "Policies": "FullAccessPolicyEC2",
    },
    "FullAccessGroupS3": {
        "Group": "FullAccessGroupS3",
        "Policies": "FullAccessPolicyS3",
    },
    "ReadAccessGroupS3": {
        "Group": "ReadAccessGroupS3",
        "Policies": "ReadAccessPolicyS3",
    },
}


def test_groups(iam_client):
    response = iam_client.list_groups()
    for group in response["Groups"]:
        assert group["GroupName"] in cxqa_iam_03_exp_data
        response_group = iam_client.list_attached_group_policies(
            GroupName=group["GroupName"]
        )
        attached_policy_name = response_group["AttachedPolicies"][0]["PolicyName"]
        assert (
            attached_policy_name == cxqa_iam_03_exp_data[group["GroupName"]]["Policies"]
        )
