# setup.py

from setuptools import setup, find_packages

setup(
    name="pi_cyber_sec",
    version="0.1.0",
    author="chetan",
    author_email="chetanjunja914@gmail.com",
    description="A Python library for cyberattack detection on a Raspberry Pi router.",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/chetan-914/pi_cyber_sec",
    packages=find_packages(where="."),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "scapy",
        "numpy",
        "pandas",
        "scikit-learn",
        "joblib",
    ],
    entry_points={
        'console_scripts': [
            'pi-detect=scripts.run_live_detection:main',
        ],
    },
)