from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="secaudit-toolkit",
    version="1.0.0",
    description="A modular security assessment toolkit for web applications and networks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Valerio porcile",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        "urllib3>=2.0.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-mock>=3.0", "responses>=0.23"],
    },
    entry_points={
        "console_scripts": [
            "secaudit=secaudit.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security, web, scanner, pentest, vulnerability, ctf",
)
