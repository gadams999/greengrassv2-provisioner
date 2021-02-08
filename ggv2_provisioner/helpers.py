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
import re
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
    iot_client = boto3.client("iot", region_name=region_name)
    iam_client = boto3.client("iam", region_name=region_name)
    try:
        # IoT role alias already exists
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
                response = iam_client.get_role(RoleName=iam_role_name)
                iam_role_arn = response["Role"]["Arn"]
                log.info(
                    f'Using existing IAM Role "{iam_role_name}" for AWS IoT Role Alias "{iot_role_alias_name}"'
                )
            except iam_client.exceptions.NoSuchEntityException as e:
                log.info(
                    f'IAM Role "{iam_role_name}" specified but does not exist, will create for AWS IoT Role Alias use'
                )
                # Create iam-role and inline-attach IAM policy
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


def provision_iot_thing(
    region_name: str,
    thing_name: str,
    certificate_id: str,
    iot_policy_name: str,
    iot_policy_file: Path,
    iot_role_alias_name,
) -> dict:
    """[summary]

    :param region_name: Region to perform actions
    :type region_name: str
    :param thing_name: Name of thing to create or validate already exists
    :type thing_name: str
    :param certificate_id: Name of IoT certificate to reference,
        will be attached to the policy and thing (thing <-> certificate <-> policy).
        If not provided and a thing is created, a new certificate will be created
        and the private key and certificate returned
    :type certificate_id: str, optional
    :param iot_policy_name: Name of IoT policy to reference, will be
        attached to the certificate. If not provided or doesn't exist,
        `iot_policy_file` must be provided
    :type iot_policy_name: str, optional
    :param iot_policy_file: Local file that contains the AWS IoT Policy to be used
        if creating a new `iot_policy_name` policy. The contents of the policy must
        be valid JSON
    :type iot_policy_file: Path, optional
    :param iot_role_alias_name: Name of AWS IoT role alias to verify it is part of the
        certificate's IoT policy for `rolealias` access
    :type iot_role_alias_name: str, optional
    :return: Dictionary of iot_thing related keys and values, using the key of `iot_device`
    :rtype: dict
    """

    iot_device = {"iot_device": {}}
    iot_client = boto3.client("iot", region_name=region_name)
    try:
        # IoT thing already exists
        response = iot_client.describe_thing(thingName=thing_name)
        log.info(f'IoT Thing "{thing_name}" already exists')
        iot_device["iot_device"]["thingName"] = response["thingName"]
        iot_device["iot_device"]["thingArn"] = response["thingArn"]
    except iot_client.exceptions.ResourceNotFoundException:
        log.info(f'IoT Thing "{thing_name}" not found, attempting to create')
        # Create thing
        try:
            response = iot_client.create_thing(thingName=thing_name)
            log.info(f'IoT Thing "{thing_name}" successfully created')
            iot_device["iot_device"]["thingName"] = response["thingName"]
            iot_device["iot_device"]["thingArn"] = response["thingArn"]
        except botocore.exceptions.ClientError as e:
            log.error(f"{e} when attempting to create thing {thing_name}")
            sys.exit(1)

    # With the thing validated, create or validate certificate

    if certificate_id is None:
        # No certificate provided, so create one
        try:
            response = iot_client.create_keys_and_certificate(setAsActive=True)
            log.info(f'created and activated certificate: {response["certificateArn"]}')
            iot_device["iot_device"]["certificateId"] = response["certificateId"]
            iot_device["iot_device"]["certificateArn"] = response["certificateArn"]
            iot_device["iot_device"]["certificatePem"] = response["certificatePem"]
            iot_device["iot_device"]["keyPair"] = response["keyPair"]
        except botocore.exceptions.ClientError as e:
            log.error(
                f"{e} while creating certificate and keys, exiting. Resources have not been rolled back"
            )
            sys.exit(1)
    else:
        # Certificate Id was provided, validate
        try:
            # Validate if certificate Id is valid and exists
            response = iot_client.describe_certificate(certificateId=certificate_id)
            log.info(
                f'Created certificate: {response["certificateDescription"]["certificateId"]}'
            )
            iot_device["iot_device"]["certificateId"] = response[
                "certificateDescription"
            ]["certificateId"]
            iot_device["iot_device"]["certificateArn"] = response[
                "certificateDescription"
            ]["certificateArn"]
        except botocore.exceptions.ClientError as e:
            log.error(
                f"{e} when attempting to describe certificate: {certificate_id}, exiting"
            )
            sys.exit(1)
        except iot_client.exceptions.ResourceNotFoundException as e:
            log.info(
                f'IoT Certificate "{certificate_id}" not found, attempting to create and activate'
            )
            try:
                response = iot_client.create_keys_and_certificate(setAsActive=True)
                log.info(
                    f'created and activated certificate: {response["certificateArn"]}'
                )
                iot_device["iot_device"]["certificateId"] = response["certificateId"]
                iot_device["iot_device"]["certificateArn"] = response["certificateArn"]
                iot_device["iot_device"]["certificatePem"] = response["certificatePem"]
                iot_device["iot_device"]["keyPair"] = response["keyPair"]
            except botocore.exceptions.ClientError as e:
                log.error(
                    f"{e} while creating certificate and keys, exiting. Resources have not been rolled back"
                )
                sys.exit(1)

    # With thing _and_ certificate validated, create or validate IoT Policy
    try:
        # Check if IoT policy already exists
        response = iot_client.get_policy(policyName=iot_policy_name)
        if not verify_alias_in_policy(
            policy_document=response["policyDocument"],
            iot_role_alias_name=iot_role_alias_name,
        ):
            # Need to add alias to existing policy
            add_role_alias_to_policy(
                iot_policy_name=iot_policy_name,
                iot_role_alias_name=iot_role_alias_name,
                region_name=region_name,
            )
        iot_device["iot_device"]["policyName"] = response["policyName"]
        iot_device["iot_device"]["policyArn"] = response["policyArn"]
    except iot_client.exceptions.ResourceNotFoundException:
        # IoT Policy doesn't exist, create from IoT Policy file
        if not iot_policy_file:
            log.error(
                "--iot-policy-file must be included when --iot-policy-name does not exist"
            )
            sys.exit(1)
        try:
            with open(iot_policy_file, "r") as f:
                policy_document = f.read()
            if not verify_alias_in_policy(
                policy_document=policy_document, iot_role_alias_name=iot_role_alias_name
            ):
                # TODO - add assumerolewithcertificate statement if it doesn't exist
                log.error(
                    f'content of --iot-policy-file must contain a valid "iot:AssumeRoleWithCertificate" statement referencing a valid AWS IoT Role Alias'
                )
                sys.exit(1)
            response = iot_client.create_policy(
                policyName=iot_policy_name, policyDocument=policy_document
            )
            iot_device["iot_device"]["policyName"] = response["policyName"]
            iot_device["iot_device"]["policyArn"] = response["policyArn"]
        except iot_client.exceptions.MalformedPolicyException:
            log.error(
                f"Contents of AWS IoT Policy file {iot_policy_file} is not valid, please review"
            )
            sys.exit(1)
        except Exception as e:
            log.error(f"{e}, while attempting to create new AWS IoT Policy")
            exit(1)

    # Thing, certificate, and policy validated, complete attachment of principal to thing and policy
    return iot_device


def add_role_alias_to_policy(
    iot_policy_name: str, iot_role_alias_name: str, region_name: str
) -> bool:
    """Update AWS IoT Policy with Role Alias access

    :param iot_policy_name: Name of AWS IoT Policy to modify
    :type iot_policy_name: str
    :param iot_role_alias_name: Name of IoT Role alias to add to policy
    :type iot_role_alias_name: str
    :param region_name: Region to perform API operations
    :type region_name: str
    :return: True if able to add Role Alias to the policy, otherwise system exit
    :rtype: bool
    """

    try:
        iot_client = boto3.client("iot", region_name=region_name)
        response = iot_client.get_policy(policyName=iot_policy_name)
        account = response["policyArn"].split(":")[4]
        role_alias_statement = {
            "Effect": "Allow",
            "Action": "iot:AssumeRoleWithCertificate",
            "Resource": f"arn:aws:iot:{region_name}:{account}:rolealias/{iot_role_alias_name}",
        }
        new_policy = response["Statement"].append(role_alias_statement)
        # Determine if a new version can be created
        response = iot_client.list_policy_versions(policyName=iot_policy_name)
        if len(response["policyVersions"]) == 5:
            # delete the oldest version
            iot_client.delete_policy_version(
                policyName=iot_policy_name,
                policyVersionId=response["policyVersions"][-1]["versionId"],
            )
        response = iot_client.create_policy_version(
            policyName=iot_policy_name,
            policyDocument=json.dumps(new_policy),
            setAsDefault=True,
        )
    except Exception as e:
        log.error(f"{e}, uncaught")
        sys.exit(1)


def verify_alias_in_policy(policy_document: str, iot_role_alias_name: str) -> bool:
    """Validates that the IoT Role Alias is referenced in the latest version of the policy document

    :param policy_document: JSON encoded string of the AWS IoT Policy
    :type policy_document: str
    :param iot_role_alias_name: AWS IoT Role Alias name to verify is _Allowed_ in the policy
    :type iot_role_alias_name: str
    :return: True if the role is referenced in the IoT Policy, otherwise False
    :rtype: bool
    """

    try:
        data = json.loads(policy_document)
    except json.decoder.JSONDecodeError as e:
        log.error(f"AWS IoT Policy is invalid JSON")
        return False

    # Check for any action that might match
    for statement in data["Statement"]:
        for action in statement["Action"]:
            # Check each action for matching actions: iot:*, iot:Assume*, ...
            if re.fullmatch(action.replace("*", ".*"), "iot:AssumeRoleWithCertificate"):
                for resource in statement["Resource"]:
                    # With matching actions, verify the role alias is provided
                    if (
                        statement["Resource"].split("/")[-1] == iot_role_alias_name
                    ) and (statement["Effect"] == "Allow"):
                        log.info(
                            f"Found matching iot:AssumeRoleWithCertificate in policy statement: {statement}"
                        )
                        return True

    # No matching statements found
    log.error(
        f"No statement for iot:AssumeRoleWithCertificate and resource {iot_role_alias_name} found in AWS IoT Policy: {policy_document}"
    )
    return False


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

    # Create or use IoT Role Alias and update results (key = iot_role_alias)
    response = provision_iot_role_alias(
        region_name=region_name,
        iot_role_alias_name=arguments.iot_role_alias_name,
        iam_role_name=arguments.iam_role_name,
        iam_policy_file=arguments.iam_policy_file,
    )
    provisioning_results.update(response)

    # Create or use Thing, Certificate and IoT Policy resource, then update results
    # (key = iot_device)
    response = provision_iot_thing(
        region_name=region_name,
        thing_name=arguments.thing_name,
        iot_role_alias_name=arguments.iot_role_alias_name,
        certificate_id=arguments.certificate_id,
        iot_policy_name=arguments.iot_policy_name,
        iot_policy_file=arguments.iot_policy_file,
    )
    provisioning_results.update(response)
