"""Process and validate arguments
Author:
    Amazon.com, Inc.

License:
    Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

    Licensed under the Apache License, Version 2.0 (the "License"). You may not use 
    this file except in compliance with the License. A copy of the License is located at

        http://aws.amazon.com/apache2.0/

    or in the "license" file accompanying this file. This file is distributed on an "AS IS" 
    BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
    License for the specific language governing permissions and limitations under the License.
"""

import argparse
import sys
import re
import errno
from pathlib import Path


def is_fqdn(hostname: str) -> str:
    """
    https://en.m.wikipedia.org/wiki/Fully_qualified_domain_name
    """
    if not 1 < len(hostname) < 253:
        raise argparse.ArgumentTypeError("invalid host name length")

    # Remove trailing dot
    if hostname[-1] == ".":
        hostname = hostname[0:-1]

    #  Split hostname into list of DNS labels
    labels = hostname.split(".")

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r"^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

    # Check that all labels match that pattern.
    if all(fqdn.match(label) for label in labels):
        return hostname
    else:
        raise argparse.ArgumentTypeError("invalid fully-qualified host name")


def is_aws_region(region: str) -> str:
    """Validate region by format only"""

    region_check = re.compile(
        r"(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d"
    )
    if region_check.match(region):
        return region
    else:
        raise argparse.ArgumentTypeError("invalid AWS region")


def is_file_ro(filename: Path) -> Path:
    """Verifies file exists and can be open for read-only

    Args:
        filename (Path): path/filename to check
    """
    try:
        with open(filename) as f:
            f.read()
            f.close()
            return filename
    except IOError as x:
        if x.errno == errno.ENOENT:
            raise argparse.ArgumentTypeError(f"filename: {filename} does not exist")
        elif x.errno == errno.EACCES:
            raise argparse.ArgumentTypeError(f"filename: {filename} cannot be read")
        else:
            raise argparse.ArgumentTypeError(f"error accessing {filename}")


def parse_arguments():
    """Parse and validate argument list required for provisioner"""
    parser = argparse.ArgumentParser()
    # Required arguments
    requiredGroup = parser.add_argument_group("required named arguments")
    requiredGroup.add_argument(
        "--root-dir",
        help="root directory of Greengrass 2 installation",
        default=Path("/greengrass/v2"),
    )
    requiredGroup.add_argument(
        "--component-default-user",
        help="default user:group for running components",
        default="ggc_user:ggc_group",
    )

    thingname_group = requiredGroup.add_mutually_exclusive_group(required=True)
    thingname_group.add_argument(
        "--thing-name",
        help="name AWS IoT thing to create",
    )
    thingname_group.add_argument(
        "--thing-arn",
        help="existing AWS IoT thing ARN to use",
    )

    # If a certificate and key pair already exists, all three arguments are required.
    # Otherwise, is assumed there are no credentials and a new certifcate and private key will be created
    credentials_group = parser.add_argument_group()
    credentials_group.add_argument(
        "--certificate-arn",
        help="existing AWS Certificate ARN to use",
    )
    credentials_group.add_argument(
        "--certificate-file",
        required="--certificate-arn" in sys.argv,
        type=is_file_ro,
        help="path to existing certificate file to copy into Greengrass directory",
    )
    credentials_group.add_argument(
        "--private-key-file",
        required="--certificate-arn" in sys.argv,
        type=is_file_ro,
        help="path to existing private key file to copy into Greengrass directory",
    )

    iot_policy_group = requiredGroup.add_mutually_exclusive_group(required=True)
    iot_policy_group.add_argument(
        "--iot-policy-arn", help="existing AWS IoT Policy ARN to attach to certificate"
    )
    iot_policy_group.add_argument(
        "--iot-policy-name", help="name of AWS IoT Policy to create"
    )
    requiredGroup.add_argument(
        "--iot-policy-file",
        required="--iot-policy-name" in sys.argv,
        type=is_file_ro,
        help="JSON formatted AWS IoT Policy file to attach to certificate",
    )

    root_ca_group = requiredGroup.add_mutually_exclusive_group(required=True)
    root_ca_group.add_argument(
        "--download-root-ca", action="store_true", help="download the Amazon Root CA"
    )
    root_ca_group.add_argument(
        "--root-ca-file",
        type=is_file_ro,
        help="path to root CA file for endpoint validation",
    )

    # Role Alias via ARN or newly named alias. If new alias, --role-alias-policy needs to be entered
    role_alias_group = requiredGroup.add_mutually_exclusive_group(required=True)
    role_alias_group.add_argument(
        "--role-alias-arn",
        help="existing AWS IoT Role Alias ARN to use for AWS service permissions",
    )
    role_alias_group.add_argument(
        "--role-alias-name", help="name of AWS IoT Role Alias to create"
    )
    requiredGroup.add_argument(
        "--role-alias-policy-file",
        required="--role-alias-name" in sys.argv,
        type=is_file_ro,
        help="JSON formatted IAM policy file to attach inline to the role alias",
    )
    requiredGroup.add_argument(
        "--iam-role-name",
        required=False,
        help="the name to assign to the IAM role referenced by the newly create role alias",
    )

    requiredGroup.add_argument(
        "--region",
        required=True,
        type=is_aws_region,
        help='region for Greengrass to provision and connect (e.g., "us-west-2")',
    )
    requiredGroup.add_argument(
        "--iot-data-endpoint",
        required=True,
        type=is_fqdn,
        help="the AWS IoT data endpoint for your AWS account",
    )
    requiredGroup.add_argument(
        "--iot-cred-endpoint",
        required=True,
        type=is_fqdn,
        help="the AWS IoT credentials endpoint for your account",
    )

    # Perform general argument processing
    args = parser.parse_args()

    # Second-level validation that cannot be performed by argparse

    return args
