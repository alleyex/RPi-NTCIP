from setuptools import setup, find_packages

setup(
    name="ntcip_server",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pyyaml",
    ],
    entry_points={
        'console_scripts': [
            'ntcip-server=ntcip_server.src.ntcip_server:main',
            'ntcip-simulator=ntcip_server.src.ntcip_simulator:main',
        ],
    },
) 