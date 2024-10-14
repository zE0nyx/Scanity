from setuptools import setup, find_packages

setup(
    name='scanity',
    version='0.1',
    author='zE0nyx',
    author_email='iamze0official@gmail.com',
    description='A Python network scanner',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/zE0nyx/Scanity',
    packages=find_packages(),
    install_requires=[
        'pyfiglet',
        'scapy',
    ],
    entry_points={
        'console_scripts': [
            'scanity=scanity:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
    include_package_data=True,
)
