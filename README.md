# pyreverse
A Python-Based Reverse Proxy Tool for HTTP Applications Without Native HTTPS Support

Pyreverse is a Python-based reverse proxy tool that allows HTTP applications without native HTTPS support to serve HTTPS traffic. This script listens for incoming HTTPS requests on the specified port and forwards them as HTTP requests to the target host and port. It also provides functionality to generate self-signed certificates using OpenSSL and serves the application on both local and public IPs. The configuration is stored in a config.ini file, which allows you to specify multiple hosts and ports to proxy simultaneously. The script utilizes multithreading to serve each proxy instance in a separate thread.




First, download the PyReverse files from their source and place them in the same directory: pyreverse.py, config.ini, and the openssl folder.

Install the requirements.txt file by running pip install -r requirements.txt in the command prompt or terminal. This will install all the necessary Python packages required by PyReverse.

Modify the config.ini file according to your connections. The configuration file consists of sections for each reverse proxy you want to set up. The sections contain the host, http_port, and https_port of the target server.

Open a PowerShell window (on Windows) or Terminal (on MacOS or Linux) in the directory where you have placed the PyReverse files.

Run the PyReverse tool by entering the following command: python pyreverse.py.

PyReverse will start running and set up the reverse proxies specified in the config.ini file. The tool will create a self-signed SSL/TLS certificate for each reverse proxy and serve HTTPS traffic on the specified https_port.

Once the reverse proxies are set up, PyReverse will print out the HTTPS addresses on which they are available, including the public IP address and local IP addresses.

Note: If you are running PyReverse on a Windows machine, make sure to run PowerShell as an administrator to avoid any permission issues.
