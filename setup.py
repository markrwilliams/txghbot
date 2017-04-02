"""
Setup file for txghbot.
"""

from setuptools import setup, find_packages

setup(name='txghbot',
      use_incremental=True,
      setup_requires=['incremental'],
      install_requires=['attrs',
                        'incremental',
                        'six',
                        'Twisted>=16.4.1'],
      extras_require={
          'dev': ['coverage', 'tox'],
      },
      packages=find_packages() + ['twisted.plugins'],
      include_package_data=True,
      license="MIT")
