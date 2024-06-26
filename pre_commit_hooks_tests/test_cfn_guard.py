"""
This module tests that the main method accepts
cfn-guard args and returns the expected error code
"""

from __future__ import annotations

from pre_commit_hooks.cfn_guard import main


def test_failing_template():
    """Test a failing case."""
    ret = main(
        [
            "validate",
            "--rules='./guard/resources/validate/rules-dir/'",
            "--data='./guard/resources/validate/data-dir/'",
        ]
    )
    assert ret == 19


def test_passing_template():
    """Test a success case."""
    ret = main(
        [
            "validate",
            "--rules='./guard/resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard'",
            # pylint: disable=C0301
            "--data='./guard/resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml'",
        ]
    )
    assert ret == 0
