"""
This module tests that the main method accepts
cfn-guard args and returns the expected error code
"""

from __future__ import annotations

from pre_commit_hooks.cfn_guard import main

import os.path


def get_guard_resource_path(relative_path):
    return os.path.join(os.path.abspath(__file__ + "/../../")) + "/guard/resources" + relative_path


def test_validate_failing_template():
    """Test a failing validate case."""
    data_dir = get_guard_resource_path("/validate/data-dir/")
    rules_dir = get_guard_resource_path("/validate/rules-dir/")
    ret = main(
        [
            data_dir,
            "--operation=validate",
            f"--rules={rules_dir}",
        ]
    )
    assert ret == 19


def test_validate_passing_template():
    """Test a success validate case."""
    first_rule = get_guard_resource_path(
        "/validate/rules-dir/s3_bucket_public_read_prohibited.guard"
    )
    second_rule = get_guard_resource_path(
        "/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard"
    )
    data = get_guard_resource_path(
        "/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml"
    )
    ret = main([data, "--operation=validate", f"--rules={first_rule}", f"--rules={second_rule}"])
    assert ret == 0


def test_passing_tests():
    """Test a success test case."""
    directory = get_guard_resource_path(
        "/validate/rules-dir/s3_bucket_public_read_prohibited.guard"
    )
    ret = main(
        [
            directory,
            "--operation=test",
            f"--dir={directory}",
        ]
    )
    assert ret == 0


def test_failing_tests():
    """Test a failing test case."""
    directory = os.path.join(os.path.abspath(__file__ + "/../")) + "/resources"
    ret = main(
        [
            directory,
            "--operation=test",
            f"--dir={directory}",
        ]
    )
    assert ret == 7
