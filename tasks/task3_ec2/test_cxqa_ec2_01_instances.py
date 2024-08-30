def test_public_instance_have_public_ip(ec2_client):
    response = ec2_client.describe_instances()
    state_of_instances = []
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            is_public = False
            for sg in instance["SecurityGroups"]:
                sg_response = ec2_client.describe_security_groups(
                    GroupIds=[sg["GroupId"]]
                )
                for ip_permission in sg_response["SecurityGroups"][0]["IpPermissions"]:
                    for ip_range in ip_permission["IpRanges"]:
                        if ip_range["CidrIp"] == "0.0.0.0/0":
                            is_public = True
                            break
            state_of_instances.append(is_public)
    assert (
        state_of_instances[0] ^ state_of_instances[1]
    ), f"Both instance are {str(state_of_instances)}"
