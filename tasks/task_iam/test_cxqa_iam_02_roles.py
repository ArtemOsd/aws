cxqa_iam_02_exp_data = {
    "FullAccessRoleEC2": {
        "Role": "FullAccessRoleEC2",
        "Policies": "FullAccessPolicyEC2",
    },
    "FullAccessRoleS3": {
        "Role": "FullAccessRoleS3",
        "Policies": "FullAccessPolicyS3",
    },
    "ReadAccessRoleS3": {
        "Role": "ReadAccessRoleS3",
        "Policies": "ReadAccessPolicyS3",
    },
}


def test_roles(iam_client):
    response = iam_client.list_roles()
    for role in response["Roles"]:
        if role["Path"] == "/" and "cdk" not in role["RoleName"]:
            assert role["RoleName"] in cxqa_iam_02_exp_data
            response_role = iam_client.list_attached_role_policies(
                RoleName=role["RoleName"]
            )
            attached_policy_name = response_role["AttachedPolicies"][0]["PolicyName"]
            assert (
                attached_policy_name
                == cxqa_iam_02_exp_data[role["RoleName"]]["Policies"]
            )
