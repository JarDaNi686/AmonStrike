from setuptools import setup, find_packages

setup(
    name="amonstrike",
    version="3.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "flask",
        "pillow",
        "pyyaml",
        "lxml",
        "dnspython",
        "tldextract",
    ],
    extras_require={
        "browser": ["playwright"],
        "full":    ["playwright","aiohttp","websockets"],
    },
)
