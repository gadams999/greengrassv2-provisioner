"""Helpers - actual logic
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

import os
import logging
import tempfile
import botocore
import boto3
from pathlib import Path

log = logging.getLogger("ggv2-provisioner")


def verify_greengrass(gg_root: Path) -> bool:
    """Reviews local install to verify it is not previously provisioned

    Args:
        gg_root (Path): Greengrass v2 root directory

    Returns:
        bool: True if Greengrass is installed but not configured
    """

    # Verify GG root exists and we can read/write files in the config/ directory
    if not os.path.isdir(gg_root + "/config"):
        log.error(f"--root-dir value: {str(gg_root + '/config')} does not exist")
        return False

    # Test access to /config
    temp_name = Path(gg_root + "/config/" + next(tempfile._get_candidate_names()))
    try:
        open(temp_name, "a").close()
    except Exception as e:
        log.error(
            f"{str(e)}, unable to access and create files in {str(gg_root + '/config')}"
        )
        return False
    # Make sure files can be deleted too
    try:
        temp_name.unlink()
    except Exception as e:
        log.error(
            f"{str(e)}, unable to delete files in {str(gg_root + '/config')}, please resolve permissions and rerun"
        )
        return False

    # Look for existing deployments
    try:
        if len(os.listdir(gg_root + "/deployments")) == 0:
            log.info(f"{str(gg_root + '/deployments')} exists and is empty, proceed")
        else:
            log.error(
                f"Greengrass appears to be configured, deployments found, {str(gg_root + '/deployments')} must be empty"
            )
            return False
    except Exception as e:
        log.error(f"{str(e)}, please review Greengrass installation")
        return False

    # Clean out the /config directory
    log.info("Removing all files from the {str(gg_root + '/config')} directory")
    try:
        for child in Path(gg_root + "/config").glob("*"):
            if child.is_file():
                log.debug(f"Removing file {child}")
                child.unlink()
    except Exception as e:
        log.error(f"{str(e)}, could not empty {str(Path(gg_root + '/config/'))}")
        return False

    # All tests passed
    return True


def verify_aws_credentials(region: str) -> bool:
    """Verifies that AWS credentials are available, but not
    that the credentials can perform all operations

    Returns:
        bool: True if credentials exist
    """

    try:
        sts = boto3.client(
            "sts",
            region_name=region,
            endpoint_url=f"https://sts.{region}.amazonaws.com/",
        )
        sts.get_caller_identity()
        log.info("STS GetCallerIdentity returned valid credentials")
    except botocore.exceptions.ClientError as e:
        log.error(f"{e}, AWS credentials not properly configured, exiting")
        return False
    except botocore.exceptions.NoCredentialsError as e:
        log.error(f"{e}, AWS credentials needed to complete provisioning steps")
        return False
    return True