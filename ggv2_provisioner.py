#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Provision and configure local Greengrass v2 installation with Cloud resources.

Usage:
    ./ggv2_provisioner.py --help

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
import logging
import time
import sys
from pathlib import Path

import tqdm
import colorlog


class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.tqdm.write(msg)
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
handler = TqdmLoggingHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s%(name)s | %(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%d-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "white",
            "SUCCESS:": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
)
log.addHandler(handler)

parser = argparse.ArgumentParser()
# Required arguments
requiredGroup = parser.add_argument_group("required named arguments")
requiredGroup.add_argument(
    "--rootdir",
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
    help="path to existing certificate file to copy into Greengrass directory",
)
credentials_group.add_argument(
    "--private-key-file",
    required="--certificate-arn" in sys.argv,
    help="path to existing private key file to copy into Greengrass directory",
)

# If an IoT policy already exists with --iot-policy-arn, make sure --thing-name or --thing-arn provided
# and optionally certificate-name
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
    help="JSON formatted AWS IoT Policy file to attach to certificate",
)


root_ca_group = requiredGroup.add_mutually_exclusive_group(required=True)
root_ca_group.add_argument(
    "--download-root-ca", action="store_true", help="download the Amazon Root CA"
)
root_ca_group.add_argument(
    "--root-ca-file", help="path to root CA for validating endpoint"
)

requiredGroup.add_argument(
    "--region",
    required=True,
    help='region for Greengrass to provision and connect (e.g., "us-west-2")',
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
    help="JSON formatted IAM policy file to attach inline to the role alias",
)
requiredGroup.add_argument(
    "--iam-role-name",
    required=False,
    help="the name to assign to the IAM role referenced by the newly create role alias",
)
args = parser.parse_args()

# Perform conditional argument checking not supported by argparse

# If creating a new thing, either no certificate info provided (create cert) or cert-arn

print(args)
