from setuptools import setup, find_packages

setup(name='txghbot',
      packages=find_packages(),
      version='16.0.0',
      install_requires=['Twisted>=16.0.0',
                        'txgithub'])
