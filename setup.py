from setuptools import setup, find_packages

setup(
    name="sage-iam",
    version="1.0.0",
    author="Sarah Modi",
    author_email="sarah@roeh.security",
    description="Sage: AWS Security Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/SarahModi/sagev1",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["boto3>=1.26.0"],
    entry_points={
        "console_scripts": ["sage=sage.cli:main"],
    },
    python_requires=">=3.7",
)
