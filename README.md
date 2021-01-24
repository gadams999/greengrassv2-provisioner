# AWS IoT Greengrass 2.0 provisioner

Command line interface to safely provision a newly installed (but not configured) Greengrass service. By default the provisioner requires all basic values for Greengrass to work with the AWS Cloud services, checks that the proper permissions are available, and then provisions the `config.yaml` and credentials for the new instance.

Once completed, the initial start of Greengrass will read the contents of `GREENGRASS_ROOT/config/config.yaml` and connect to AWS IoT Greengrass services.

# Quick start

First, install AWS IoT Greengrass as a local service, but _do not_ start prior to running the provisioner. Follow the [Setting up AWS IoT Greengrass Version 2](https://docs.aws.amazon.com/greengrass/v2/developerguide/setting-up.html) to verify all dependencies are installed. Next, complete  [Install the AWS IoT Greengrass Core software](https://docs.aws.amazon.com/greengrass/v2/developerguide/install-greengrass-core-v2.html) steps 1 and 2, then _**skip step 3**_ and run the following command to install the AWS IoT Greengrass Core software:

```shell
sudo -E java -Droot="/greengrass/v2" -Dlog.store=FILE \
  -jar ./GreengrassCore/lib/Greengrass.jar \
  --component-default-user ggc_user:ggc_group \
  --provision false \
  --setup-system-service true \
  --start false
```

This will install the software and setup for Systemd startup, but will not provision or start the local instance. 



