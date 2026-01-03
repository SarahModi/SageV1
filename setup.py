from setuptools import setup, find_packages

setup(
    name="Sage-iam",
    version="1.0.0",
    author="Sarah Modi",
    description="Sage: AWS Security Scanner - Find the 5 misconfigurations that cause breaches",
    url="https://github.com/SarahModi/SageV1",
    packages=find_packages(),
    install_requires=["boto3>=1.26.0"],
    entry_points={
        "console_scripts": ["sage=sage.cli:main"],
    },
)
