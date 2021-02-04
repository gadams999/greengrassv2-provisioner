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
import sys
import logging
import tempfile
import botocore
import boto3
import argparse
import json
from pathlib import Path

log = logging.getLogger("ggv2-provisioner")

assume_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "credentials.iot.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def json_to_dict(filename: Path) -> dict:
    """Verify file contains valid JSON and converts to dictionary

    NOTE: Does not perform filename validation, caught by general exception

    Args:
        filename (Path): filename to read

    Returns:
        dict: converted JSON from file
    """

    try:
        with open(filename) as f:
            data = json.load(f)
        return data
    except Exception as e:
        log.error(f"{e}, invalid JSON in {filename}, exiting")
        sys.exit(1)


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


def provision_iot_role_alias(
    region_name: str, iot_role_alias_name: str, iam_role_name: str, iam_policy_file: str
) -> dict:
    """Validate and create IoT Role Alias

    Args:
        region_name (str): region to perform actions
        iot_role_alias_name (str): IoT Role Alias name to use or create
        (optional) iam_role_name (str): IAM Role to create or reference for IoT Role Alias
        (optional) iam_policy_file (str): IAM policy to attach to IAM Role if creating

    Returns:
        dict: Non-empty details for "iot_role_alias"
    """

    iot_role_alias = {"iot_role_alias": {}}

    try:
        # IoT role alias already exists
        iot_client = boto3.client("iot", region_name=region_name)
        response = iot_client.describe_role_alias(roleAlias=iot_role_alias_name)
        log.info(f'IoT Role Alias "{iot_role_alias_name}" found, returning')
        iot_role_alias["iot_role_alias"]["roleAlias"] = response[
            "roleAliasDescription"
        ]["roleAlias"]
        iot_role_alias["iot_role_alias"]["roleAliasDescription"] = response[
            "roleAliasDescription"
        ]["roleAliasArn"]
        iot_role_alias["iot_role_alias"]["roleArn"] = response["roleAliasDescription"][
            "roleArn"
        ]
        return iot_role_alias
    except iot_client.exceptions.ResourceNotFoundException:
        log.info(
            f'IoT Role Alias "{iot_role_alias_name}" not found, attempting to create'
        )
        if iam_role_name is None:
            log.error(
                "--iam-role-name required when creating new --iot-role-alias-name resource"
            )
            exit(1)
        else:
            # Role name provided, verify before creating IoT Role Alias
            try:
                iam_client = boto3.client("iam", region_name=region_name)
                response = iam_client.get_role(RoleName=iam_role_name)
                iam_role_arn = response["Role"]["Arn"]
                log.info(
                    f'Using existing IAM Role "{iam_role_name}" for AWS IoT Role Alias "{iot_role_alias_name}"'
                )
            except iam_client.exceptions.NoSuchEntityException as e:
                log.info(
                    f'IAM Role "{iam_role_name}" specified but does not exist, will create for AWS IoT Role Alias use'
                )
                # TODO Create iam-role w/ attached IAM policy
                if iam_policy_file is None:
                    log.error(
                        "--iam-policy-file required when creating new --iam-role-name resource"
                    )
                    sys.exit(1)
                try:
                    # Verify IAM policy file is valid JSON
                    policy_document = json_to_dict(iam_policy_file)
                    response = iam_client.create_role(
                        RoleName=iam_role_name,
                        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                        Description="Created by ggv2_provisioner",
                    )
                    iam_role_arn = response["Role"]["Arn"]
                    log.info(
                        f'Created IAM Role "{iam_role_name}" usable by IoT Role Alias "{iot_role_alias_name}"'
                    )
                    response = iam_client.put_role_policy(
                        RoleName=iam_role_name,
                        PolicyName="GGv2ProvisionerBase",
                        PolicyDocument=json.dumps(policy_document),
                    )
                    log.info(
                        f'Applied policy from {iam_policy_file} to IAM Role "{iam_role_name}"'
                    )

                except Exception as e:
                    log.error(f"{e}, exiting")
                    sys.exit(1)

            # Create IoT Role alias with IAM role
            try:
                response = iot_client.create_role_alias(
                    roleAlias=iot_role_alias_name,
                    roleArn=iam_role_arn,
                )
                log.info(
                    f'IoT Role Alias "{iot_role_alias_name}" created with IAM role "{iam_role_name}"'
                )
                response = iot_client.describe_role_alias(roleAlias=iot_role_alias_name)
                iot_role_alias["iot_role_alias"]["roleAlias"] = response[
                    "roleAliasDescription"
                ]["roleAlias"]
                iot_role_alias["iot_role_alias"]["roleAliasDescription"] = response[
                    "roleAliasDescription"
                ]["roleAliasArn"]
                iot_role_alias["iot_role_alias"]["roleArn"] = response[
                    "roleAliasDescription"
                ]["roleArn"]
                return iot_role_alias
            except Exception as e:
                log.error(f"{e}, exiting")
                sys.exit(1)


def provision_greengrass(arguments: argparse) -> dict:
    """Orchstrates and completes all provisioning processes based on
    incoming validated argument list

    Args:
        arguments (argparse): validated arguments

    Returns:
        dict: all status and values from provisioning steps
    """

    # define commonly used values
    region_name = arguments.region

    provisioning_results = {}

    # Create or use IoT Role Alias
    response = provision_iot_role_alias(
        region_name=region_name,
        iot_role_alias_name=arguments.iot_role_alias_name,
        iam_role_name=arguments.iam_role_name,
        iam_policy_file=arguments.iam_policy_file,
    )
    provisioning_results.update(response)
    print(provisioning_results)
