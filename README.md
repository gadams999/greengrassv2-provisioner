# AWS IoT Greengrass 2 Provisioner

The AWS IoT Greengrass 2 Provisioner (Provisioner) is command line interface to safely provision a newly installed (but not presently configured) AWS IoT Greengrass service. The _Provisioner_ performs all the steps to fully provision all AWS Cloud resources and then create the local files in the AWS IoT Greengrass root directory that reference and use the returned credentials.

Once completed, the initial start of AWS IoT Greengrass will read the contents of `GREENGRASS_ROOT/config/config.yaml` and connect to AWS IoT Greengrass services.

## Installation

Clone the repository and install dependencies. As the provisioner is normally only needed for single operations, once the repository is cloned, install the package dependencies under the default user which will be used with the `sudo -E` install command.

```shell
cd ~
git clone https://github.com/gadams999/greengrassv2-provisioner.git
cd greengrassv2-provisioner
pip3 install --user -r requirements.txt
```

The ggv2-provisioner is supported on Python 3.6 and above.

> :warning: **You will need to run `ggv2_provisioner` as root (sudo)** - the `pip3 install` will place the requirements into the users' directory, and be used through the `sudo -E` flag when calling the _Provisioner_.

## How to use

## Install AWS IoT Greengrass

Prior to running the _Provisioner_, download and unzip the installation media and set AWS credentials.

Follow the [Setting up AWS IoT Greengrass Version 2](https://docs.aws.amazon.com/greengrass/v2/developerguide/setting-up.html) to verify all dependencies are installed, and next complete the [Install the AWS IoT Greengrass Core software](https://docs.aws.amazon.com/greengrass/v2/developerguide/install-greengrass-core-v2.html) steps 1 through 3 (exporting AWS credentials), then **STOP** (_do not perform step 4_).

## Provision a New AWS IoT Greengrass Core

Next, run the _Provisioner_ which will do the following:

1. Validate all resource inputs
1. Create the Greengrass root directory
1. Create all cloud resources and then save the credentials and rootCA file to the Greengrass root directory
1. Create the default `config.yaml` in the system's temporary directory
1. Run the Greengrass installation steps passing in the `config.yaml` and setting up to run as a system service

When finished, Greengrass will be installed and running on the local host.

### Option 1 - Provision All Resources

If you need to deploy all the required resources to run AWS IoT Greengrass, use this process. The command will provision the following new resources:

- IAM Role with policy of provided permissions to be used by the AWS IoT Role Alias
- AWS IoT specific resources:
  - AWS IoT Role Alias used by AWS IoT Greengrass components to access other AWS services
  - AWS IoT Thing which maps to the AWS IoT Greengrass Core
  - AWS IoT Certificate (PEM encoded certificate and private key)
  - AWS IoT Policy used by the AWS IoT Greengrass Core to interact with `iot` and `greengrass` actions
  - Attach the Certificate to the Thing and Policy

Run the _Provisioner_ command to complete the operations.

Note: The command line below references sample IAM and IoT policy documents located in the `samples/` directory. Please review and change the actions and resources as needed. Also, you will need, at minimum, the local AWS permissions listed in the **FAQ Permissions** section.

```shell
# Run from the ggv2_provisioner directory
# Replace all "Test-" values with what you want to call the resources
cd ~/greengrassv2-provisioner
sudo -E python3 -m ggv2_provisioner \
  --root-dir /greengrass/v2 \
  # Change the directory to where you unzipped the nucleus file
  --gg-install-media-dir ~/GreengrassCore \
  # Replace with target region
  --region YOUR_REGION \
  --thing-name "Test-gg-device" \
  --download-root-ca \
  --iot-role-alias-name "Test-gg-role-alias" \
  --iam-role-name "Test-gg-role" \
  # Review and modify as needed
  --iam-policy-file samples/iam_base_permissions.json \
  --iot-policy-name "Test-iot-policy" \
  # Review and modify as needed
  --iot-policy-file samples/iot_base_permissions.json
```

This will complete _all_ the operations needed for a new AWS IoT Greengrass Core to be provisioned in the cloud and configured locally.

### Option 2 - Provision a Thing with an Existing IoT Role Alias

If you already have some of the resources provisions, such as the IAM Role and AWS IoT Role Alias, referencing them by name will have the _Provisioner_ validate the resource exists and then use that. For instance, if an AWS IoT Role Alias name `Test-gg-role-alias` has already been provisioned and references an IAM Role, you can just reference `--iot-role-alias-name "Test-gg-role-alias"`. In this case, the provisioning command would look like:

> TODO

## Caveats

The _Provisioner_ is prescriptive in certain approaches to the provisioning process. You may need to take these into consideration.

- **Component default user/group** - These must be set initially through the _Greengrass.jar_ installation process by providing the `--component-default-user ggc_user:ggc_group` setup argument. The _Provisioner_ does not support changing of the default user and group.
- **AWS permissions** - The _Provisioner_ requires different AWS permissions to perform the various resource creation steps. Please ensure you current AWS credentials are sufficient to perform all the steps.
- **No roll-back of resources** - The _Provisioner_ creates resources in an synchronous manner. If a steps fails halfway through the process, the previously created resources are not rolled back and deleted. It is recommended to review and correct issues at they arise
- **Local file naming and location** - The certificate, private key, and Root CA files use static names (e.g., `ThingName-certificate.pem`, `ThingName-private-key.pem`, and `RootCA.pem`). Also, the files are place into to root directory and referenced with absolute file name paths.

## Troubleshooting and Frequently Asked Questions

### What are the minimum permissions required to run the Provisioner?

These are the [IAM Actions](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) required to run all steps of the _Provisioner_. If some operations are not being performed, such as the creation of an IAM Role, those can removed from any minimum permissions. Due to the variability of naming, `Resource` values should be set to `"*"` unless you will scope down naming conventions.

| Action                         | Description                                                                       | Access Level | Provisioner Use                                                                                              |
| ------------------------------ | --------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------ |
| `iam:CreateRole`               | from docs                                                                         | Write        | Create new IAM Role for AWS IoT Role Alias                                                                   |
| `iam:GetRole`                  | from docs                                                                         | Read         | Determine if IAM Role already exists                                                                         |
| `iam:PutRolePolicy`            | from docs                                                                         | Write        | Add contents of `--iam-policy-file` to newly created IAM Role                                                |
| `iot:AttachPolicy`             | from docs                                                                         | Write        | Attach certificate to AWS IoT Policy                                                                         |
| `iot:AttachThingPrincipal`     | from docs                                                                         | Write        | Attach certificate to AWS IoT Thing (Greengrass Core)                                                        |
| `iot:CreateKeysAndCertificate` | from docs                                                                         | Write        | Create and activate new X.509 client certificate and return certificate and private key                      |
| `iot:CreatePolicy`             | from docs                                                                         | Write        | Create a new AWS IoT Policy with policy document containing `iot:AssumeRoleWithCertificate` Allow permission |
| `iot:CreatePolicyVersion`      | from docs                                                                         | Write        | Create a new version of policy for an existing AWS IoT Policy                                                |
| `iot:CreateRoleAlias`          | from docs                                                                         | Write        | Create new AWS IoT Role Alias                                                                                |
| `iot:CreateThing`              | from docs                                                                         | Write        | Create new AWS IoT Thing to represent Greengrass Core                                                        |
| `iot:DeletePolicyVersion`      | from docs                                                                         | Write        | Delete the oldest AWS IoT Policy version to allow for new version                                            |
| `iot:DescribeCertificate`      | from docs                                                                         | Read         | Determine if AWS IoT Certificate already exists                                                              |
| `iot:DescribeRoleAlias`        | from docs                                                                         | Read         | Determine if AWS IoT Role Alias already exists                                                               |
| `iot:DescribeThing`            | from docs                                                                         | Read         | Determine if AWS IoT Thing already exists                                                                    |
| `iot:GetPolicy`                | from docs                                                                         | Read         | Determine if AWS IoT Policy already exists                                                                   |
| `iot:ListPolicyVersions`       | from docs                                                                         | Read         | Determine if at limit (5) of AWS IoT Policy versions                                                         |
| `sts:GetCallerIdentity`        | Returns details about the IAM identity whose credentials are used to call the API | Read         | Build resource Arns for IAM and IoT policies                                                                 |

# Coding, TODO's, etc.

Process to automate creation of GG Thing, cert, rolealias, etc. and use Ansible to install and perform initial deployment. Intent is for script that runs on the GG device and based on needed approach creates all cloud side resources and updates all files needed prior to first run.

The three approaches:

1. Uses locally defined AWS credentials to generate all cloud resources and deploys to GGv2 root directory.
1. Uses a bootstrap certificate and deployed Fleet Provisioning pipeline to complete the steps via Lambda.
1. Uses a bootstrap certificate or API key to call API Gateway to completed the provisioning steps.

**NOTE**: Provisioning only takes place on an installed, but not running AWS IoT Greengrass software deployment. It is expected to be part of an automation process such as Ansible, or GGv2 software embedded into a base install such as Yocto/OE.

Locally, a script would take in:

- Region
- AWS credentials from normal process of environment variables or local credentials file
- thingName to create
- thingGroup to create and place the thingName in, existing thingGroup, or optionally no thingGroup
- iotPolicy file to create, arn of existing policy, or create a default policy with minimal permissions needed

The AWS IoT Policy needs to contain normal `iot:` actions for connect, publish, subscribe, but also must contain the `iot:AssumeRoleWithCertificate` action and reference the AWS IoT Role Alias to use or be created. Here is an example default policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:Connect",
        "iot:Publish",
        "iot:Subscribe",
        "iot:Receive",
        "greengrass:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["iot:AssumeRoleWithCertificate"],
      "Resource": "arn:aws:iot:REGION:AWS_ACCOUNT:rolealias/your_role_alias_name"
    }
  ]
}
```

- Certificate to create (AWS IoT), CSR to use for AWS IoT, arn of existing certificate, or certificate/key from BYoCA
- Role alias name to include as policy attached to certificate (if new role alias, it will create the IAM role and an inline policy with this default policy (note - this is overly permissive and should only be used for testing purposes):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:DescribeCertificate",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
        "iot:Connect",
        "iot:Publish",
        "iot:Subscribe",
        "iot:Receive",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    }
  ]
}
```

For artifact access, this needs to be added to role alias role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"
    }
  ]
}
```

The minimal created `config.yaml` will contain the following, with the `REPLACE_WITH_` text using the provisioned values:

```yaml
---
system:
  certificateFilePath: "REPLACE_WITH_ABSOLUTE_PATH"
  privateKeyPath: "REPLACE_WITH_ABSOLUTE_PATH"
  rootCaPath: "REPLACE_WITH_ABSOLUTE_PATH"
  rootpath: "REPLACE_WITH_ROOT_DIR"
  thingName: "REPLACE_WITH_THING_NAME"
services:
  aws.greengrass.Nucleus:
    componentType: "NUCLEUS"
    configuration:
      awsRegion: "REPLACE_WITH_REGION"
      componentStoreMaxSizeBytes: 10000000000
      deploymentPollingFrequencySeconds: 15
      envStage: "prod"
      iotCredEndpoint: "REPLACE_WITH_ENDPOINT"
      iotDataEndpoint: "REPLACE_WITH_ENDPOINT"
      iotRoleAlias: "REPLACE_WITH_ROLE_ALIAS"

      logging: {}
      networkProxy:
        proxy: {}
      runWithDefault:
        posixUser: "ggc_user:ggc_group"
    version: "2.0.3"
  main:
    dependencies:
      - "aws.greengrass.Nucleus"
    lifecycle: {}
```

Systemd config file to create:

```
[Unit]
Description=Greengrass Core

[Service]
Type=simple
PIDFile=/greengrass/v2/alts/loader.pid
RemainAfterExit=no
Restart=on-failure
RestartSec=10
ExecStart=/bin/sh /greengrass/v2/alts/current/distro/bin/loader

[Install]
WantedBy=multi-user.target
```

## User stories

1. I want to develop locally and create and configure AWS IoT Greengrass resources with local AWS credentials stored.
1. I have a vanilla system that I will pass credentials to complete provisioning (SSM, Ansible) via a local provisioner.
1. I have an embedded firmware with certificate and private key that I want to use to register a certificate (JITP) and configure Greengrass.
1. I have a bootstrap certificate that I will use to register.
1. I have an API key that I will use to register.
