#!/usr/bin/env python3
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

import logging
import json
import sys
from pathlib import Path

import tqdm
import colorlog

from ggv2_provisioner import *


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


log = logging.getLogger("ggv2-provisioner")
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


def main():

    # Process arguments
    arguments = provisioner_argparse.parse_arguments()
    log.debug(f"command arguments: {arguments}")

    # TODO - remove once new process of provisioner -> config.yaml -> install script runs
    # Verify that Greengrass installation media exists
    print("Verifying Greengrass installation media")
    if not helpers.verify_greengrass_install_media(arguments.gg_install_media_dir):
        sys.exit(1)

    # Verify that the root directory for Greengrass does not exist
    print(f"Verifying {arguments.root_dir} does not exist or is empty")
    if not helpers.verify_target_directory_empty(arguments.root_dir):
        sys.exit(1)

    # Verify that AWS credentials are available for use
    print("Verifying AWS credentials are available for use")
    if not helpers.verify_aws_credentials(arguments.region):
        sys.exit(1)

    # Start provisioning process - Builds a dictionary of results to then use to process a
    # new config.yaml file, populate files, or return a singular object for light-weight app
    # to process.

    print("Starting the Cloud provisioning process")
    response = helpers.provision_greengrass(arguments)
    print(json.dumps(response))

    # with files save locally, run the GG installation process
    response = helpers.install_greengrass(
        arguments.gg_install_media_dir, arguments.root_dir
    )


if __name__ == "__main__":
    main()
