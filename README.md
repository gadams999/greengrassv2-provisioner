# AWS IoT Greengrass 2.0 provisioner

Command line interface to safely provision a newly installed (but not configured) Greengrass service. By default the provisioner requires all basic values for Greengrass to work with the AWS Cloud services, checks that the proper permissions are available, and then provisions the `config.yaml` and credentials for the new instance.

Once completed, the initial start of Greengrass will read the contents of `GREENGRASS_ROOT/config/config.yaml` and connect to AWS IoT Greengrass services.

# Quick start

First, install AWS IoT Greengrass as a local service, but _do not_ start prior to running the provisioner. Follow the [Setting up AWS IoT Greengrass Version 2](https://docs.aws.amazon.com/greengrass/v2/developerguide/setting-up.html) to verify all dependencies are installed. Next, complete [Install the AWS IoT Greengrass Core software](https://docs.aws.amazon.com/greengrass/v2/developerguide/install-greengrass-core-v2.html) steps 1 and 2, then _**skip step 3**_ and run the following command to install the AWS IoT Greengrass Core software:

```shell
sudo -E java -Droot="/greengrass/v2" -Dlog.store=FILE \
  -jar ./GreengrassCore/lib/Greengrass.jar \
  --component-default-user ggc_user:ggc_group \
  --provision false \
  --start false
```

This will install the software but will not provision or start the local instance of Greengrass. At this point, the image or distro can be completed. The next set of steps require connectivity to the Internet to complete.

Next, run the provisioner which will do the following:

1. Validate that Greengrass is not running
1. Remove all files in `$ROOT/config`
1. Based on input for either creating resources or just referencing, create a new `$ROOT/config/config.yaml` file
1. If selected, create a system startup command for Greengrass.
   1. If selected, start Greengrass locally

# Caveats

The provisioner is currently prescriptive in what it does. At present, there are some constraints:

- Component default user/group - These must be set initially through the _Greengrass.jar_ `--component-default-user ggc_user:ggc_group` setup argument then passed through to the _ggv2_provisioner_ `--component-default-user` argument (default value of ggc_user:ggc_group).

# Coding, TODO's, etc.

Process to automate creation of GG Thing, cert, rolealias, etc. and use Ansible to install and perform initial deployment. Intent is for script that runs on the GG device and based on needed approach creates all cloud side resources and updates all files needed prior to first run.

The three approaches:

1. Uses locally defined AWS credentials to generate all cloud resources and deploys to GGv2 root directory.
1. Uses a bootstrap certificate and deployed Fleet Provisioning pipeline to complete the steps via Lambda.
1. Uses a bootstrap certificate or API key to call API Gateway to completed the provisioning steps.

**NOTE**: Provisioning only takes place on an installed, but not running Greengrass software deployment. It is expected to be part of an automation process such as Ansible, or GGv2 software embedded into a base install such as Yocto/OE.

Locally, a script would take in:

- Region
- AWS credentials from normal process of environment variables or local credentials file
- thingName to create
- thingGroup to create and place the thingName in, existing thingGroup, or optionally no thingGroup
- iotPolicy file to create, arn of existing policy, or create a default policy with minimal permissions needed
- Certificate to create (AWS IoT), CSR to use for AWS IoT, arn of existing certificate, or certificate/key from BYoCA
- Role alias name to include as policy attached to certificate (if new role alias, it will create the IAM role and an inline policy with this default policy:

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

The minimal created `config.yaml` will contain:

```yaml
---
system:
  certificateFilePath: ""
  privateKeyPath: ""
  rootCaPath: ""
  rootpath: "/greengrass/v2"
  thingName: ""
services:
  aws.greengrass.Nucleus:
    componentType: "NUCLEUS"
    configuration:
      awsRegion: "REGION"
      componentStoreMaxSizeBytes: 10000000000
      deploymentPollingFrequencySeconds: 15
      envStage: "prod"
      iotCredEndpoint: ""
      iotDataEndpoint: ""

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

1. I want to develop locally and create and configure Greengrass resources with local AWS credentials stored.
1. I have a vanilla system that I will pass credentials to complete provisioning (SSM, Ansible) via a local provisioner.
1. I have an embedded firmware with certificate and private key that I want to use to register a certificate (JITP) and configure Greengrass.
1. I have a bootstrap certificate that I will use to register.
1. I have an API key that I will use to register.
