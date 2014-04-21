import os
from setuptools import setup, find_packages

setup(

    name = 'massweb',
    version = '0.0.1',
    description = 'Fast Web Fuzzing and Scanning',
    long_description = 'Hyperion Gray\'s fast scanning and fuzzing module. Used in PunkSPIDER 3.0.',
    url = 'https://bitbucket.org/acaceres/massweb',
    license = 'Apache 2.0',
    author = 'Alejandro Caceres',
    author_email = 'contact@hyperiongray.com',
    packages = find_packages(),
    include_package_data = True,
    classifiers = [ "Development Status :: 2 - Pre-Alpha",
                    'Intended Audience :: Developers',
                    'Programming Language :: Python :: 2.7',
                    'Programming Language :: Python']
)
