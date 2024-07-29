import pytest_check as check
import requests


def test_request_check_public_instance_app(instances):
    instance = instances["public"]
    public_instance_ip = instance["PublicIpAddress"]
    response = requests.get(f"http://{public_instance_ip}")
    assert response.status_code == 200
    response_data = response.json()
    check.equal(
        response_data["availability_zone"], instance["Placement"]["AvailabilityZone"]
    )
    check.equal(response_data["private_ipv4"], instance["PrivateIpAddress"])
    check.equal(response_data["region"], instance["Placement"]["AvailabilityZone"][:-1])


def test_request_check_private_instance_app(instances, forward_80_port_via_ssh):
    local_host, local_port = forward_80_port_via_ssh
    instance = instances["private"]
    response = requests.get(f"http://{local_host}:{local_port}")
    assert response.status_code == 200
    response_data = response.json()
    check.equal(
        response_data["availability_zone"], instance["Placement"]["AvailabilityZone"]
    )
    check.equal(response_data["private_ipv4"], instance["PrivateIpAddress"])
    check.equal(response_data["region"], instance["Placement"]["AvailabilityZone"][:-1])
