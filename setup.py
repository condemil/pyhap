from os import path

from setuptools import setup

with open(path.join(path.dirname(__file__), 'README.rst')) as f:
    long_description = f.read().strip()

setup(
    name='pyhap',
    version='0.1.1',
    packages=['pyhap', 'pyhap.characteristics'],
    install_requires=[
        'cryptography',
        'ed25519',
        'zeroconf',
    ],
    description='Python implementation of HomeKit Accessory Protocol',
    long_description=long_description,
    url='https://github.com/condemil/pyhap',
    license='MIT',
    author='Dmitry Budaev',
    python_requires='>=3.6.0',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Home Automation',
        'Topic :: Software Development :: Libraries',
    ],
)
