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
parser.add_argument(
    "--rootdir",
    help="root directory of Greengrass 2 installation",
    default=Path("/greengrass/v2"),
)
parser.add_argument(
    "--component-default-user",
    help="default user:group for running components",
    default="ggc_user:ggc_group",
)

thingname_group = parser.add_mutually_exclusive_group(required=True)
thingname_group.add_argument(
    "--thing-name",
    help="name AWS IoT thing to create",
)
thingname_group.add_argument(
    "--thing-arn",
    help="existing AWS IoT thing ARN to use",
)

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

root_ca_group = parser.add_mutually_exclusive_group(required=True)
root_ca_group.add_argument(
    "--download-root-ca", action="store_true", help="download the Amazon Root CA"
)
root_ca_group.add_argument(
    "--root-ca-file", help="path to root CA for validating endpoint"
)

parser.add_argument(
    "--region",
    required=True,
    help='region for Greengrass to provision and connect (e.g., "us-west-2")',
)

args = parser.parse_args()
print(args)
