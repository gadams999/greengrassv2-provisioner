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
from pathlib import Path

log = logging.getLogger("ggv2-provisioner")


def verify_greengrass(gg_root: Path) -> bool:
    """Reviews local install to verify it is not previously provisioned

    Args:
        gg_root (Path): Greengrass v2 root directory

    Returns:
        bool: True if installation is correct otherwise exit() with error set
    """

    # Verify GG root exists and we can read/write files in the config/ directory
    if not os.path.isdir(gg_root + "/config"):
        log.error(f"--root-dir value: {str(gg_root + '/config')} does not exist")
        return False

    # Test access to /config
    temp_name = gg_root + "/config" + next(tempfile._get_candidate_names())
    if not open(temp_name, "a").close():
        log.error(f"unable to create files in {str(gg_root + '/config')}")
        return False

    # All tests passed
    return True