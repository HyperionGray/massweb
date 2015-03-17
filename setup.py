import os
from setuptools import setup, find_packages

setup(
    name = 'massweb',
    version = '0.3.0',
    description = 'Fast Web Fuzzing and Scanning',
    long_description = 'Hyperion Gray\'s fast scanning and fuzzing module. Used in PunkSPIDER 3.0.',
    url = 'https://bitbucket.org/acaceres/massweb',
    license = 'Apache 2.0',
    author = 'Alejandro Caceres, Chris Koepke',
    author_email = 'contact@hyperiongray.com, me@haxwithaxe.net',
    packages = find_packages(),
    include_package_data = True,
    install_requires = ['requests', 'beautifulsoup4', 'html5lib', 'alabaster'],
    classifiers = [ "Development Status :: 4 - Beta",
                    'Intended Audience :: Developers',
                    'Programming Language :: Python :: 2.7',
                    'Programming Language :: Python']
)
