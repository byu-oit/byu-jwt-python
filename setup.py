#!/usr/bin/env python

import sys
from setuptools import setup, find_packages
version = '1.1.3'

if sys.version_info == (2, 7,) or sys.version[0] == 3:
    sys.stderr.write("This version of byu_jwt requires Python 2.7 or 3.*\n")
    sys.exit(-1)

# we only use the subset of markdown that is also valid reStructuredText so
# that our README.md works on both github (markdown) and pypi (reStructuredText)
with open("README.md") as rm_file:
    long_description = rm_file.read()

setup(name='byu_jwt',
      version=version,
      description='A python JWT validator that does all the BYU specific stuff as well.',
      long_description=long_description,
      author='BYU OIT Application Development',
      author_email='paul.eden@byu.edu',
      url='https://github.com/byu-oit-appdev/byu-jwt-python',
      py_modules=['byu_jwt'],
      data_files=[('', ['README.md', 'LICENSE'])],
      test_suite="byu_jwt.test",
      license="Apache 2.0",
      install_requires=list(filter(lambda item: item, open('requirements.txt').read().split('\n'))),
      zip_safe=True)
