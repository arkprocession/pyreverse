# pyreverse
A Python-Based Reverse Proxy Tool for HTTP Applications Without Native HTTPS Support

Pyreverse is a Python-based reverse proxy tool that allows HTTP applications without native HTTPS support to serve HTTPS traffic. This script listens for incoming HTTPS requests on the specified port and forwards them as HTTP requests to the target host and port. It also provides functionality to generate self-signed certificates using OpenSSL and serves the application on both local and public IPs. The configuration is stored in a config.ini file, which allows you to specify multiple hosts and ports to proxy simultaneously. The script utilizes multithreading to serve each proxy instance in a separate thread.
