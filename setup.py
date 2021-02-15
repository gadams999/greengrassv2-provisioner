from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.readlines()

long_description = "Automated tool to provision Greengrass 2.0"

setup(
    name="ggv2_provisioner",
    version="0.0.8",
    author="Gavin Adams",
    author_email="gavinaws@amazon.com",
    url="https://github.com/gadams999/greengrassv2-provisioner",
    description="Greengrass 2.0 command line provisioner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    packages=find_packages(),
    entry_points={"console_scripts": ["ggv2-provisioner = ggv2_provisioner:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">3.6",
    keywords="greengrass ggv2 provision provisioner",
    install_requires=requirements,
    zip_safe=False,
)
