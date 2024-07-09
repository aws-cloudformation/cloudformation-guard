"""
This module contains the logic for the cfn-guard pre-commit hook
"""

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import argparse
from pathlib import Path
from typing import Sequence, Union
from urllib.request import Request, urlopen

BIN_NAME = "cfn-guard"
UNSUPPORTED_OS_MSG = "Unsupported operating system. Could not install cfn-guard."
UNKNOWN_OPERATION_MSG = (
    "Unknown operation. cfn-guard pre-commit-hook only supports validate and test commands."
)
# Hardcode this so the pre-commit-hook rev is tied to a specific version
GUARD_BINARY_VERSION = "3.1.1"

release_urls_dict = {
    # pylint: disable=C0301
    "darwin": "https://github.com/aws-cloudformation/cloudformation-guard/releases/download/TAG/cfn-guard-v3-macos-latest.tar.gz",
    # pylint: disable=C0301
    "linux": "https://github.com/aws-cloudformation/cloudformation-guard/releases/download/TAG/cfn-guard-v3-ubuntu-latest.tar.gz",
    # pylint: disable=C0301
    "windows": "https://github.com/aws-cloudformation/cloudformation-guard/releases/download/TAG/cfn-guard-v3-windows-latest.tar.gz",
}
supported_oses = ["linux", "darwin", "windows"]
current_os = platform.system().lower()
install_dir = os.path.join(os.path.expanduser("~"), ".cfn-guard-pre-commit")


class CfnGuardPreCommitError(Exception):
    """Custom exception class for specific error scenarios."""

    def __init__(self, message, code=None):
        """
        Initialize the CfnGuardPreCommitError object.

        Args:
            message (str): The error message.
            code (int, optional): An optional error code.
        """
        self.message = message
        self.code = code
        super().__init__(message)

    def __str__(self):
        """
        Return a string representation of the CfnGuardPreCommitError object.
        """
        if self.code is not None:
            return f"{self.message} (Code: {self.code})"
        return self.message


def request(url: str):
    """Roll our own get request method to avoid extra dependencies"""

    # Explicitly set the headers to avoid User-Agent "Python-urllib/x.y"
    # https://docs.python.org/3/howto/urllib2.html#headers
    return Request(url, headers={"User-Agent": "Mozilla/5.0"})


def get_binary_name() -> str:
    """Get an OS specific binary name"""

    return BIN_NAME + (".exe" if current_os == "windows" else "")


def install_cfn_guard():
    """
    Install the cfn-guard to the install_dir to avoid
    global version conflicts with existing installations, rust,
    and cargo.
    """
    binary_name = get_binary_name()

    if current_os in supported_oses:
        url = release_urls_dict[current_os].replace("TAG", GUARD_BINARY_VERSION)
        # Download tarball of release from Github
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            with urlopen(url) as response:
                shutil.copyfileobj(response, temp_file)

        # Create the install_dir if it doesn't exist
        os.makedirs(install_dir, exist_ok=True)

        with tarfile.open(temp_file.name, "r:gz") as tar:
            # Extract tarball members to install_dir
            for member in tar.getmembers():
                if member.isdir():
                    continue  # Skip directories
                # Extract the filename from the full path within the archive
                filename = os.path.basename(member.name)
                # Join the install_dir path and the filename to get the full target path
                file_path = os.path.join(install_dir, filename)
                # Open the archived file
                with tar.extractfile(member) as source:
                    # Create a new file using the file_path with write binary mode
                    with open(file_path, "wb") as target:
                        # Copy the contents of the archived file(s) to the target file
                        shutil.copyfileobj(source, target)

        binary_path = os.path.join(install_dir, binary_name)
        os.chmod(binary_path, 0o755)
        os.remove(temp_file.name)
    else:
        raise CfnGuardPreCommitError(f"{UNSUPPORTED_OS_MSG}: {current_os}", code=1)


def run_cfn_guard(args: str) -> int:
    """Pass arguments to and run cfn-guard"""

    binary_name = get_binary_name()
    binary_path: str = str(Path(os.path.join(install_dir, binary_name)))

    if os.path.exists(binary_path):
        project_root: str = os.getcwd()
        cmd = f"{binary_path} {args}"

        try:
            result = subprocess.run(cmd, cwd=project_root, shell=True, check=True)
            return result.returncode
        except subprocess.CalledProcessError as e:
            return e.returncode
    else:
        # Install cfn-guard if it doesn't exist and then run it.
        install_cfn_guard()
        return run_cfn_guard(args)


def main(argv: Union[Sequence[str], None] = None) -> int:
    """Entry point for the pre-commit hook"""
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Files to validate")
    parser.add_argument("--operation", action="append", help="cfn-guard operation", required=True)
    parser.add_argument("--rules", action="append", help="Rules file/directory")
    parser.add_argument("--dir", action="append", help="Test & rules directory")

    args = parser.parse_args(argv)

    exit_code = 0

    for filename in args.filenames:
        if args.operation[0] == "validate":
            cmd = f"validate --rules={args.rules[0]} --data={filename}"
        elif args.operation[0] == "test":
            cmd = f"test --dir={args.dir[0]}"
        else:
            raise CfnGuardPreCommitError(UNKNOWN_OPERATION_MSG)

        result = run_cfn_guard(cmd)
        if result != 0:
            exit_code = result

    return exit_code


# Handle invocation from python directly
if __name__ == "__main__":
    raise SystemExit(main())
