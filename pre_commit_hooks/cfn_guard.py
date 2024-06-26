"""
This module contains the logic for the cfn-guard pre-commit hook
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Sequence, Union
from urllib.request import Request, urlopen

# pylint: disable=C0301
LATEST_RELEASE_URL = (
    "https://api.github.com/repos/aws-cloudformation/cloudformation-guard/releases/latest"
)
BIN_NAME = "cfn-guard"
UNSUPPORTED_OS_MSG = "Unsupported operating system. Could not install cfn-guard."

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


def get_latest_tag() -> str:
    """Get the latest release tag from Github"""

    req = request(LATEST_RELEASE_URL)

    with urlopen(req) as response:
        data = response.read().decode("utf-8")
        return json.loads(data)["tag_name"]


def get_binary_name() -> str:
    """Get an OS specific binary name"""

    return BIN_NAME + (".exe" if current_os == "windows" else "")


def install_cfn_guard():
    """
    Install the latest cfn-guard to the install_dir to avoid
    global version conflicts with existing installations, rust,
    and cargo.
    """
    latest_tag = get_latest_tag()
    binary_name = get_binary_name()

    if current_os in supported_oses:
        url = release_urls_dict[current_os].replace("TAG", latest_tag)
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


def run_cfn_guard(args: Sequence[str]) -> int:
    """Pass arguments to and run cfn-guard"""

    binary_name = get_binary_name()
    binary_path: str = str(Path(os.path.join(install_dir, binary_name)))

    if os.path.exists(binary_path):
        project_root: str = os.getcwd()
        cmd = [binary_path] + list(args)

        try:
            result = subprocess.run(" ".join(cmd), cwd=project_root, shell=True, check=True)
            return result.returncode
        except subprocess.CalledProcessError as e:
            return e.returncode
    else:
        # Install cfn-guard if it doesn't exist and then run it.
        install_cfn_guard()
        return run_cfn_guard(args)


def main(argv: Union[Sequence[str], None] = None) -> int:
    """Entry point for the pre-commit hook"""

    # This only serves to chop the first arg (the filename) when running the script directly
    if argv is None:
        argv = sys.argv[1:]

    return run_cfn_guard(argv)


# Handle invocation from python directly
if __name__ == "__main__":
    raise SystemExit(main())
