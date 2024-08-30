def test_public_inst_have_access_via_ssh_and_http(instances, ec2_client):
    allowed_ports = [22, 80]
    instance = instances["public"]
    for sg in instance["SecurityGroups"]:
        sg_response = ec2_client.describe_security_groups(GroupIds=[sg["GroupId"]])
        for permission in sg_response["SecurityGroups"][0]["IpPermissions"]:
            assert permission.get("FromPort") in allowed_ports
            assert permission.get("ToPort") in allowed_ports
            assert any(
                ip_range["CidrIp"] == "0.0.0.0/0"
                for ip_range in permission.get("IpRanges")
            )


def test_private_inst_have_access_from_public_inst_via_ssh_and_http(
    instances, ec2_client
):
    allowed_ports = [22, 80]
    public_instance_sg_id = instances["public"]["SecurityGroups"][0]["GroupId"]
    public_instance_user_id = instances["public"]["IamInstanceProfile"]["Arn"][13:25]
    private_instance = instances["private"]
    for sg in private_instance["SecurityGroups"]:
        sg_response = ec2_client.describe_security_groups(GroupIds=[sg["GroupId"]])
        for permission in sg_response["SecurityGroups"][0]["IpPermissions"]:
            assert permission.get("FromPort") in allowed_ports
            assert permission.get("ToPort") in allowed_ports
            assert not any(
                ip_range["CidrIp"] == "0.0.0.0/0"
                for ip_range in permission.get("IpRanges")
            )
            for user_group_pair in permission.get("UserIdGroupPairs"):
                assert user_group_pair.get("GroupId") == public_instance_sg_id
                assert user_group_pair.get("UserId") == public_instance_user_id


def test_inst_has_access_to_internet(ec2_client):
    response = ec2_client.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            for sg in instance["SecurityGroups"]:
                sg_response = ec2_client.describe_security_groups(
                    GroupIds=[sg["GroupId"]]
                )
                for permission in sg_response["SecurityGroups"][0][
                    "IpPermissionsEgress"
                ]:
                    assert any(
                        ip_range["CidrIp"] == "0.0.0.0/0"
                        for ip_range in permission.get("IpRanges")
                    )
