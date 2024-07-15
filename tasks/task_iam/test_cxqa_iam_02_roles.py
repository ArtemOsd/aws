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
            response_role = iam_client.list_role_policies(RoleName=role["RoleName"])
            policy_names = response_role["PolicyNames"]
            expected_policy = cxqa_iam_02_exp_data[role["RoleName"]]["Policies"]
            check.is_in(
                expected_policy,
                policy_names,
                f'Policy is not added to {role["RoleName"]} role',
            )
