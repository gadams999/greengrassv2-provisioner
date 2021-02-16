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
import inspect
import zipfile
import tempfile
import subprocess
import shutil

import requests
from pathlib import Path
from typing import Optional as Optional

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


def read_certificate_file(certificate_file: Path) -> str:
    """Read the contents of the local X.509 certificate file and returns the string

    :param certificate_file: X.509 client certificate to read
    :type certificate_file: Path
    :return: PEM encoded certificate
    :rtype: str
    """

    # the certificate format is not modified
    with open(certificate_file, "r") as f:
        data = f.read()
    return data


def read_private_key_file(private_key_file: Path) -> str:
    """Read the contents of the local private key file and then map to the same format
        returned by the `CreateKeysAndCertificates` response

    :param private_key_file: Private key file
    :type private_key_file: Path
    :return: PEM encoded private key, NOTE: the public key section is included but left blank.
        The return should be mapped to an object named `keyPair`
    :rtype: str

    .. _CreateKeysAndCertificates: https://docs.aws.amazon.com/iot/latest/apireference/API_CreateKeysAndCertificate.html

    """

    # the certificate format is not modified
    with open(private_key_file, "r") as f:
        data = f.read()
    return {"PublicKey": "", "PrivateKey": data}


def write_ggv2_config(
    provisioning_results: dict,
    root_dir: str,
    region_name: str,
    iot_cred_endpoint: str,
    iot_data_endpoint: str,
):
    """Creates the default `config.yaml` file used during first run of Greengrass
    Nucleus

    :param provisioning_results: Processed results of thing, role_alias, and other
        details.
    :type provisioning_results: dict
    :param root_dir: Root directory where Greengrass is installed
    :type root_dir: str
    :param region_name: Region for Greengrass to connect and operate
    :type region_name: str
    :param iot_cred_endpoint: AWS IoT Credential Provider endpoint
    :type iot_cred_endpoint: str
    :param iot_data_endpoint: AWS IoT Core data endpoint
    :type iot_data_endpoint: str
    """

    # Format the template placeholders. Other content can be added to this
    # as needed, ensure proper YAML indentations. For empty indexes represented
    # as braces such as foo: {}, use double braces in the template. For example:
    # foo: {{}} will render to foo: {}
    config_yaml_template = inspect.cleandoc(
        """
            ---
            system:
              certificateFilePath: "{certificate_file_path}"
              privateKeyPath: "{private_key_path}"
              rootCaPath: "{root_ca_path}"
              rootpath: "{root_dir}"
              thingName: "{thing_name}"
            services:
              aws.greengrass.Nucleus:
                componentType: "NUCLEUS"
                configuration:
                  awsRegion: "{region}"
                  componentStoreMaxSizeBytes: 10000000000
                  deploymentPollingFrequencySeconds: 15
                  envStage: "prod"
                  iotCredEndpoint: "{iot_cred_endpoint}"
                  iotDataEndpoint: "{iot_data_endpoint}"
                  iotRoleAlias: "{iot_role_alias}"
                  logging: {{}}
                  networkProxy:
                    proxy: {{}}
                  runWithDefault:
                    posixUser: "ggc_user:ggc_group"
                version: "2.0.3"
              main:
                dependencies:
                  - "aws.greengrass.Nucleus"
                lifecycle: {{}}
    """
    ).format(
        certificate_file_path=provisioning_results["credential_files"][
            "certificate_file_name"
        ],
        private_key_path=provisioning_results["credential_files"][
            "private_key_file_name"
        ],
        root_ca_path=provisioning_results["root_ca_file"]["root_ca_file_name"],
        root_dir=root_dir,
        thing_name=provisioning_results["iot_device"]["thingName"],
        region=region_name,
        iot_cred_endpoint=iot_cred_endpoint,
        iot_data_endpoint=iot_data_endpoint,
        iot_role_alias=provisioning_results["iot_role_alias"]["roleAlias"],
    )

    # Save the config.yaml file to temporary directory

    with open(Path(tempfile.gettempdir(), "config.yaml"), "w") as f:
        f.write(config_yaml_template)


def write_root_ca(
    root_dir: str, root_ca_file: Optional[str] = None, download_root_ca: bool = True
) -> dict:
    """Either downloads or writes an existing Amazon root CA file to the `root_dir` and returns the
    filename and path under key of `root_ca_file`

    :param root_dir: Location to write the CA file
    :type root_dir: str
    :param root_ca_file: Filename to read if `download_root_ca` is set to `False`
    :type root_ca_file: str, optional
    :param download_root_ca: Downloads the Amazon root CA if set True, defaults to True
    :type download_root_ca: bool
    :return: Full path of the root CA file as `credentials_files` object
    :rtype: dict
    """

    root_ca_content = ""
    if download_root_ca:
        root_ca_content = requests.get(
            "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
        ).text
    else:
        try:
            with open(Path(root_ca_file), "r") as f:
                root_ca_content = f.read()
        except Exception as e:
            log.error(f"{e}, could not read --root-ca-file content")

    # Write the file out!
    root_ca_file_name = Path() / root_dir / "RootCA.pem"
    with open(root_ca_file_name, "w") as f:
        f.write(root_ca_content)

    return {"root_ca_file": {"root_ca_file_name": str(root_ca_file_name)}}


def write_credential_files(
    root_dir: Path,
    certificate_file: str,
    private_key_file: str,
    certificate_file_name: Optional[Path] = None,
    private_key_file_name: Optional[Path] = None,
) -> dict:
    """Write the credential files to $GG_ROOT directory and return the name used.

    :param root_dir: Directory to save credential files
    :type root_dir: (Path)
    :param certificate_file: Certificate contents to save
    :type certificate_file: str
    :param private_key_file: Private key contents to save
    :type private_key_file: str
    :param certificate_file_name: Filename and path for saving `certificate_file` contents
    :type certificate_file_name: (Path), optional
    :param private_key_file_name: Filename and path for saving `private_ky_file` contents
    :type private_key_file_name: (Path), optional
    :return: Full path of credential and certificate filenames as `credential_files` object
    :rtype: dict of (Path)
    """

    if certificate_file_name is None:
        # TODO - make the filename from the certificate CN/hash
        certificate_file_name = Path() / root_dir / "ThingName-certificate.pem"
    else:
        # Use the filename provided
        certificate_file_name = Path() / root_dir / certificate_file.name

    if private_key_file_name is None:
        # TODO - make the filename from the certificate CN/hash
        private_key_file_name = Path() / root_dir / "ThingName-private-key.pem"
    else:
        # Use the filename provided
        private_key_file_name = Path() / root_dir / private_key_file_name.name

    # Write the the files
    with open(certificate_file_name, "w") as f:
        f.write(certificate_file)
    log.info(f"wrote certificate file contents to {str(certificate_file_name)}")

    with open(private_key_file_name, "w") as f:
        f.write(private_key_file)
    log.info(f"wrote private key file contents to {str(private_key_file_name)}")

    return {
        "credential_files": {
            "certificate_file_name": str(certificate_file_name),
            "private_key_file_name": str(private_key_file_name),
        }
    }


def verify_greengrass_install_media(root_dir: Path) -> bool:
    """Verifies that the unzipped Greengrass files are available to run the
        installation script. Also verifies that java is on the path.
    :param root_dir: Root directory where the `bin`, `conf`, and `lib` directories are located,
        verify that `lib/Greengrass.jar` is there.
    :type root_dir: Path
    :return: True if installation media is available, otherwise False
    :rtype: bool
    """

    log.info("Checking for unzipped Greengrass installation media")
    if zipfile.is_zipfile(Path(root_dir, "lib", "Greengrass.jar").expanduser()):
        log.info("installation media found")
    else:
        log.error(
            f"installation file {str(Path(root_dir, 'lib', 'Greengrass.jar').expanduser())} not found, exiting"
        )
        return False

    # Verify other dependencies needed to install Greengrass
    if shutil.which("java") is None:
        log.error("java executable not found on path, exiting")
        return False

    # All dependencies passed
    return True


def verify_target_directory_empty(root_dir: Path) -> bool:
    """Reviews target installation directory to make sure it doesn't exist or is empty. The
        Greengrass installation process with create or populate the directory.

    :param root_dir: Target Greengrass installlation directory
    :type root_dir: Path
    :return: True if directory is empty or does not exist
    :rtype: bool
    """

    if Path(root_dir).is_dir():
        # Directory exists, ensure it's empty
        if any(Path(root_dir).iterdir()):
            log.error(f"target installation directory {root_dir} is not empty, exiting")
            return False

    return True


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
    certificate_file: str,
    private_key_file: str,
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
    :param certificate_file: Qualified local file that contains the X.509 client
        certificate if `certificate_id` was provided
    :type certificate_file: pathlib.Path, optional
    :param private_key_file: Qualified local file that contains the X.509 client
        certificate's private key, if `certificate_id` was provided
    :type private_key_file: pathlib.Path, optional
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
                f'Validated certificate: {response["certificateDescription"]["certificateId"]}'
            )
            iot_device["iot_device"]["certificateId"] = response[
                "certificateDescription"
            ]["certificateId"]
            iot_device["iot_device"]["certificateArn"] = response[
                "certificateDescription"
            ]["certificateArn"]
            iot_device["iot_device"]["certificatePem"] = read_certificate_file(
                certificate_file
            )
            iot_device["iot_device"]["keyPair"] = read_private_key_file(
                private_key_file
            )
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
        log.info(f"AWS IoT Policy {iot_policy_name} already exists")
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
            response = iot_client.create_policy(
                policyName=iot_policy_name, policyDocument=policy_document
            )
            if not verify_alias_in_policy(
                policy_document=policy_document, iot_role_alias_name=iot_role_alias_name
            ):
                # Need to add alias to existing policy
                add_role_alias_to_policy(
                    iot_policy_name=iot_policy_name,
                    iot_role_alias_name=iot_role_alias_name,
                    region_name=region_name,
                )
            log.info(
                f"created AWS IoT Policy {iot_policy_name} and added iot:AssumeRoleWithCertificate action for AWS IoT Role Alias {iot_role_alias_name}"
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

    # attach certificate to policy
    try:
        response = iot_client.attach_policy(
            policyName=iot_device["iot_device"]["policyName"],
            target=iot_device["iot_device"]["certificateArn"],
        )
        log.info(
            f'successfully attached certificate {iot_device["iot_device"]["certificateArn"]} to policy {iot_device["iot_device"]["policyName"]}'
        )
    except botocore.exceptions.ClientError as e:
        log.error(
            f"{e} while attaching certificate to AWS IoT Policy, exiting. Resources have not been rolled back"
        )
        sys.exit(1)
    # Attach certificate to thing
    try:
        response = iot_client.attach_thing_principal(
            thingName=iot_device["iot_device"]["thingName"],
            principal=iot_device["iot_device"]["certificateArn"],
        )
        log.info(
            f'successfully attached certificate {iot_device["iot_device"]["certificateId"]} to AWS IoT thing  {iot_device["iot_device"]["thingName"]}'
        )
    except botocore.exceptions.ClientError as e:
        log.error(
            f"{e} while attaching certificate to AWS IoT THing, exiting. Resources have not been rolled back"
        )
        sys.exit(1)

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

        # From the active version of the policy, get the account and load
        # policy statement array
        account = response["policyArn"].split(":")[4]
        policy_document = json.loads(response["policyDocument"])
        role_alias_statement = {
            "Effect": "Allow",
            "Action": "iot:AssumeRoleWithCertificate",
            "Resource": f"arn:aws:iot:{region_name}:{account}:rolealias/{iot_role_alias_name}",
        }
        # Update the policy document dict with the needed Role Alias statement
        policy_document["Statement"].append(role_alias_statement)
        # Determine if a new version can be created
        response = iot_client.list_policy_versions(policyName=iot_policy_name)
        if len(response["policyVersions"]) == 5:
            # delete the oldest version
            r = iot_client.delete_policy_version(
                policyName=iot_policy_name,
                policyVersionId=response["policyVersions"][-1]["versionId"],
            )
        response = iot_client.create_policy_version(
            policyName=iot_policy_name,
            policyDocument=json.dumps(policy_document),
            setAsDefault=True,
        )
    except botocore.exceptions.ClientError as e:
        log.error(f"{e}, uncaught")
        sys.exit(1)
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
        log.debug(f"verify data dict is: {data}")
    except json.decoder.JSONDecodeError as e:
        log.error(f"AWS IoT Policy is invalid JSON")
        return False

    # Check for any action that might match
    for statement in data["Statement"]:
        # Statements can contain a list of Actions or a single Action as a string
        if type(statement["Action"]) is str:
            # Single action, create a single entry list
            statement["Action"] = [statement["Action"]]
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
    log.warning(
        f"No statement for iot:AssumeRoleWithCertificate and resource {iot_role_alias_name} found in AWS IoT Policy: {policy_document}"
    )
    return False


def get_endpoint(region_name: str, endpoint_type: str) -> str:
    """Query and return the specific endpoint

    :param region_name: Region to obtain the endpoint
    :type region_name: str
    :param endpoint_type: Endpoint type to query
    :type endpoint_type: str
    :return: The FQDN of the endpoint
    :rtype: str
    """

    iot_client = boto3.client("iot", region_name=region_name)
    try:
        response = iot_client.describe_endpoint(endpointType=endpoint_type)
        log.info(
            f"Endpoint for type: {endpoint_type} is: {response['endpointAddress']}"
        )
        return response["endpointAddress"]
    except botocore.exceptions.ClientError as e:
        log.error(
            f"Invalid response {e} when attempting to describe endpoint type of {endpoint_type}"
        )
        sys.exit(1)
    return response


def install_greengrass(gg_install_media_dir: str, root_dir: str) -> bool:
    """Runs the Greengrass installation process with a prescriptive set of flags


    :param gg_install_media_dir: Root of where the `lib/Greengrass.jar` file is located.
        NOTE: After installation this directory must not be deleted.
    :type gg_install_media_dir: str
    :param root_dir: Root directory to install Greengrass
    :type root_dir: str
    :return: True if installation operation was successful, otherwise will exit with an error
    :rtype: bool
    """

    args = [
        "java",
        f'-Droot="{str(root_dir)}"',
        "-Dlog.store=FILE",
        "-jar",
        f'{Path(gg_install_media_dir, "lib", "Greengrass.jar")}',
        "--component-default-user",
        "ggc_user:ggc_group",
        "--provision",
        "false",
        "--start",
        "false",
        "--setup-system-service",
        "true",
        "--init-config",
        Path(tempfile.gettempdir(), "config.yaml"),
    ]
    try:
        subprocess.run(args=args, shell=False, check=True)
        return True
    except Exception as e:
        log.error(e)


def provision_greengrass(arguments: argparse) -> dict:
    """Orchstrates and completes all provisioning processes based on
        incoming validated argument list

    :param arguments: Validated command line arguments
    :type arguments: argparse
    :return: Results from provisioning steps
    :rtype: dict
    """

    # define commonly used values
    region_name = arguments.region

    provisioning_results = {}

    # Create or use IoT Role Alias and update results
    # (key = iot_role_alias)
    response = provision_iot_role_alias(
        region_name=region_name,
        iot_role_alias_name=arguments.iot_role_alias_name,
        iam_role_name=arguments.iam_role_name,
        iam_policy_file=arguments.iam_policy_file,
    )
    provisioning_results.update(response)
    log.debug(
        f"provisioning results after role alias: {json.dumps(provisioning_results)}"
    )

    # Create or use Thing, Certificate and IoT Policy resource, then update results
    # (key = iot_device)
    response = provision_iot_thing(
        region_name=region_name,
        thing_name=arguments.thing_name,
        iot_role_alias_name=arguments.iot_role_alias_name,
        certificate_id=arguments.certificate_id,
        certificate_file=arguments.certificate_file,
        private_key_file=arguments.private_key_file,
        iot_policy_name=arguments.iot_policy_name,
        iot_policy_file=arguments.iot_policy_file,
    )
    provisioning_results.update(response)
    log.debug(
        f"provisioning results after iot thing: {json.dumps(provisioning_results)}"
    )

    # With all cloud resources created, save or copy credentials to $GG_ROOT

    # Create $GG_ROOT
    try:
        os.makedirs(Path(arguments.root_dir).expanduser())
    except Exception as e:
        log.error(e)

    # Write the certificate and private key to $GG_ROOT
    # ( key = filenames)
    response = write_credential_files(
        root_dir=arguments.root_dir,
        certificate_file=provisioning_results["iot_device"]["certificatePem"],
        private_key_file=provisioning_results["iot_device"]["keyPair"]["PrivateKey"],
    )
    provisioning_results.update(response)
    # Download and write rootCA
    if arguments.download_root_ca:
        response = write_root_ca(
            root_dir=arguments.root_dir,
            download_root_ca=True,
        )
    else:
        response = write_root_ca(
            root_dir=arguments.root_dir,
            root_ca_file=arguments.root_ca_file,
            download_root_ca=False,
        )
    provisioning_results.update(response)

    # If data and credential endpoints were not provided, obtain

    if arguments.iot_cred_endpoint is not None:
        iot_cred_endpoint = arguments.iot_cred_endpoint
    else:
        iot_cred_endpoint = get_endpoint(
            region_name=region_name, endpoint_type="iot:CredentialProvider"
        )

    if arguments.iot_data_endpoint is not None:
        iot_data_endpoint = arguments.iot_data_endpoint
    else:
        iot_data_endpoint = get_endpoint(
            region_name=region_name, endpoint_type="iot:Data-ATS"
        )

    # Generate and write config.yaml to temporary directory
    write_ggv2_config(
        provisioning_results=provisioning_results,
        region_name=region_name,
        root_dir=arguments.root_dir,
        iot_cred_endpoint=iot_cred_endpoint,
        iot_data_endpoint=iot_data_endpoint,
    )

    # Call Greengrass install process

    return provisioning_results
