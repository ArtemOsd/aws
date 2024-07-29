def test_instance_type(ec2_client):
    response = ec2_client.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            assert instance["InstanceType"] == "t2.micro"


def test_instance_tags(ec2_client):
    response = ec2_client.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            tags = instance["Tags"]
            cloudx_tag = None
            for tag in tags:
                if tag["Key"] == "cloudx":
                    cloudx_tag = tag
            assert f"{cloudx_tag['Key']}: {cloudx_tag['Value']}" == "cloudx: qa"


def test_root_block_device_size(ec2_client):
    response = ec2_client.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            for block_device in instance["BlockDeviceMappings"]:
                if block_device["DeviceName"] == "/dev/xvda":
                    root_block_device = block_device
            volume_id = root_block_device["Ebs"]["VolumeId"]

            # Describe the volume to get its size
            volume = ec2_client.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
            size_in_gb = volume["Size"]
            assert f"{size_in_gb} GB" == "8 GB"


def test_instance_os(ec2_client):
    response = ec2_client.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            ami_id = instance["ImageId"]
            resp = ec2_client.describe_images(ImageIds=[ami_id])
            assert "Amazon Linux 2" in resp["Images"][0]["Description"]


def test_public_instance_have_public_ip(ec2_client):
    response = ec2_client.describe_instances()
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
            if is_public:
                assert "PublicIpAddress" in instance

            else:
                assert "PublicIpAddress" not in instance
