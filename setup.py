from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="containerguard",
    version="0.1.0",
    author="Ayaan Syed",
    author_email="therealyaan9876@example.com",
    description="A comprehensive container security scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ayaan-cis/containerguard",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.8",
        "docker>=7.1.0",
        "rich>=13.9.4",
        "pyyaml>=6.0.2",
        "requests>=2.32.3",
        "pandas>=2.2.3",
        "plotly>=6.0.1",
        "jinja2>=3.1.6",
        "pydantic>=2.11.0",
        "typer>=0.15.2",
    ],
    entry_points={
        "console_scripts": [
            "containerguard=containerguard.cli:main",
        ],
    },
)