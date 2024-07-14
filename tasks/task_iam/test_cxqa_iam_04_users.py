import pytest_check as check

cxqa_iam_04_exp_data = {
    "FullAccessUserEC2": {"User": "FullAccessUserEC2", "Group": "FullAccessGroupEC2"},
    "FullAccessUserS3": {"User": "FullAccessUserS3", "Group": "FullAccessGroupS3"},
    "ReadAccessUserS3": {"User": "ReadAccessUserS3", "Group": "ReadAccessGroupS3"},
}


def test_groups(iam_client):
    response = iam_client.list_users()
    for user in response["Users"]:
        if iam_client.get_user()["User"]["UserName"] == user["UserName"]:
            continue
        check.is_in(
            user["UserName"],
            cxqa_iam_04_exp_data,
            f'{user["UserName"]} is not in expected data',
        )
        response_user = iam_client.list_groups_for_user(UserName=user["UserName"])
        attached_group_name = response_user["Groups"][0]["GroupName"]
        check.equal(
            attached_group_name,
            cxqa_iam_04_exp_data[user["UserName"]]["Group"],
            f'Wrong group attached to {user["UserName"]} user',
        )
