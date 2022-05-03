#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""


# Always prefer setuptools over distutils
from setuptools import setup
# To use a consistent encoding
from codecs import open
from os import path

__version__ = "8.0.3"

description = "A Python package and CLI for parsing aggregate and " \
              "forensic DMARC reports"

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='parsedmarc',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=__version__,

    description=description,
    long_description=long_description,

    # The project's main homepage.
    url='https://domainaware.github.io/parsedmarc',

    # Author details
    author='Sean Whalen',
    author_email='whalenster@gmail.com',

    # Choose your license
    license='Apache 2.0',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        "Intended Audience :: Information Technology",
        'Operating System :: OS Independent',


        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: Apache Software License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],

    # What does your project relate to?
    keywords='DMARC, reporting, parser',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=["parsedmarc", "parsedmarc.resources", "parsedmarc.mail"],
    package_data={
            "parsedmarc.resources": ["*.mmdb"]
    },


    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    # py_modules=["parsedmarc"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['dnspython>=2.0.0', 'expiringdict>=1.1.4',
                      'publicsuffix2>=2.20190812', 'xmltodict>=0.12.0',
                      'geoip2>=3.0.0', 'urllib3>=1.25.7',
                      'requests>=2.22.0', 'imapclient>=2.1.0',
                      'dateparser>=1.1.1',
                      'mailsuite>=1.6.1',
                      'elasticsearch<7.14.0',
                      'elasticsearch-dsl==7.4.0',
                      'kafka-python>=1.4.4',
                      'tqdm>=4.31.1',
                      'lxml>=4.4.0',
                      'boto3>=1.16.63',
                      'msgraph-core>=0.2.2',
                      'azure-identity>=1.8.0'
                      'google-api-core>=2.4.0',
                      'google-api-python-client>=2.35.0',
                      'google-auth>=2.3.3',
                      'google-auth-httplib2>=0.1.0',
                      'google-auth-oauthlib>=0.4.6',
                      ],

    entry_points={
        'console_scripts': ['parsedmarc=parsedmarc.cli:_main'],
    }
)
