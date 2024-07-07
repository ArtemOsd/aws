import pytest_check as check

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
            check.is_in(
                role["RoleName"],
                cxqa_iam_02_exp_data,
                f'{role["RoleName"]} is not in expected data',
            )
            response_role = iam_client.list_attached_role_policies(
                RoleName=role["RoleName"]
            )
            attached_policy_name = response_role["AttachedPolicies"][0]["PolicyName"]
            check.equal(
                attached_policy_name,
                cxqa_iam_02_exp_data[role["RoleName"]]["Policies"],
                f'Wrong policy attached to role {role["RoleName"]}',
            )
