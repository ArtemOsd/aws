import pytest_check as check
import requests

expected_app_keys = ["availability_zone", "private_ipv4", "region"]


def test_request_check_public_instance_app(instances):
    instance = instances["public"]
    public_instance_ip = instance["PublicIpAddress"]
    response = requests.get(f"http://{public_instance_ip}")
    assert response.status_code == 200
    check.is_in("application/json", response.headers["content-type"])
    response_data = response.json()
    for expected_key in expected_app_keys:
        check.is_in(expected_key, response_data.keys())
    check.equal(
        response_data.get("availability_zone"),
        instance["Placement"]["AvailabilityZone"],
    )
    check.equal(response_data.get("private_ipv4"), instance["PrivateIpAddress"])
    check.equal(
        response_data.get("region"), instance["Placement"]["AvailabilityZone"][:-1]
    )


def test_request_check_private_instance_app(instances, forward_80_port_via_ssh):
    local_host, local_port = forward_80_port_via_ssh
    instance = instances["private"]
    response = requests.get(f"http://{local_host}:{local_port}")
    assert response.status_code == 200
    check.is_in("application/json", response.headers["content-type"])
    response_data = response.json()
    for expected_key in expected_app_keys:
        check.is_in(expected_key, response_data.keys())
    check.equal(
        response_data.get("availability_zone"),
        instance["Placement"]["AvailabilityZone"],
    )
    check.equal(response_data.get("private_ipv4"), instance["PrivateIpAddress"])
    check.equal(
        response_data.get("region"), instance["Placement"]["AvailabilityZone"][:-1]
    )
