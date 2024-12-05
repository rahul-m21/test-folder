from setuptools import setup, find_packages

setup(
    name="crypto-demo",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography==39.0.1",
        "requests==2.28.1",
    ],
)
