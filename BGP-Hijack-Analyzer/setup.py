from setuptools import setup, find_packages

setup(
    name="bgp-hijack-analyzer",
    version="1.0.0",
    description="Detect BGP prefix hijacks, sub-prefix hijacks and route leaks against a historical baseline.",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "rich>=13.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "bgp-analyzer=bgp_analyzer.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
)
