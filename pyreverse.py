import os
import ssl
import http.server
import socketserver
import configparser
import urllib.request
import threading
from urllib.parse import urlparse
from http.client import HTTPResponse
import socket
import functools
import requests
from requests import get
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import datetime
import time
import ipaddress

class ReverseProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, target_host, target_port, *args, **kwargs):
        self.target_host = target_host
        self.target_port = target_port
        super().__init__(*args, **kwargs)

    def do_request(self):
        target_url = f"http://{self.target_host}:{self.target_port}{self.path}"
        req = urllib.request.Request(target_url, method=self.command, headers=self.headers, data=self.rfile.read(int(self.headers.get('Content-Length', 0))))

        try:
            with urllib.request.urlopen(req) as response:
                self.send_response(response.status)
                for key, value in response.getheaders():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response.read())
        except urllib.error.HTTPError as e:
            if e.code == 401 and "WWW-Authenticate" in e.headers:
                # Prompt the user for their credentials
                self.send_response(401)
                self.send_header("WWW-Authenticate", e.headers["WWW-Authenticate"])
                self.end_headers()

                # Forward authentication headers
                if "Authorization" in self.headers:
                    req.add_header("Authorization", self.headers["Authorization"])

                try:
                    with urllib.request.urlopen(req) as response:
                        self.send_response(response.status)
                        for key, value in response.getheaders():
                            self.send_header(key, value)
                        self.end_headers()
                        self.wfile.write(response.read())
                except urllib.error.HTTPError as e:
                    self.send_error(e.code, e.reason)
                except Exception as e:
                    self.send_error(500, str(e))

            else:
                self.send_error(e.code, e.reason)
        except Exception as e:
            self.send_error(500, str(e))


    def do_GET(self):
        self.do_request()

    def do_POST(self):
        self.do_request()

    def do_PUT(self):
        self.do_request()

    def do_DELETE(self):
        self.do_request()

    def do_PATCH(self):
        self.do_request()

    def do_HEAD(self):
        self.do_request()

    def do_OPTIONS(self):
        self.do_request()

    def do_CONNECT(self):
        self.do_request()
        
        
def check_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
            return True
        except socket.error:
            return False    


def get_public_ip():
    try:
        ip = get("https://api.ipify.org").text
    except requests.exceptions.RequestException:
        ip = "N/A"
    return ip

def get_local_ips():
    local_ips = []
    hostname = socket.gethostname()
    for ip in socket.getaddrinfo(hostname, None):
        local_ips.append(ip[4][0])
    return list(set(local_ips))

def run_proxy(host, http_port, https_port, stop_event):
    if not check_port(host, http_port):
        print(f"No application running on {host}:{http_port}. Skipping proxy setup.")
        return

    cert_dir = os.path.join("certificates", str(https_port))
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        os.makedirs(cert_dir, exist_ok=True)

        print("Generating SSL certificate and key...")
        print(f"Certificate path: {cert_file}")
        print(f"Key path: {key_file}")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MyDept"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        with open(cert_file, "wb") as f:
            f.write(builder.public_bytes(serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))

    HandlerClass = functools.partial(ReverseProxyHTTPRequestHandler, host, http_port)
    httpd = socketserver.TCPServer(("0.0.0.0", https_port), HandlerClass)  # Bind to all interfaces
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.timeout = 1  # Add this line to set a timeout for handle_request

    local_ips = get_local_ips()
    public_ip = get_public_ip()

    print(f"Serving HTTPS on the following addresses:")
    for local_ip in local_ips:
        if ':' not in local_ip:  # Filter out IPv6 addresses
            print(f"- https://{local_ip}:{https_port}")
    print(f"- Public IP: https://{public_ip}:{https_port}")

    try:
        while not stop_event.is_set():
            httpd.handle_request()
    except KeyboardInterrupt:
        httpd.shutdown()

class Proxy:
    def __init__(self, host, http_port, https_port):
        self.host = host
        self.http_port = http_port
        self.https_port = https_port
        self.stop_event = threading.Event()
        self.proxy_thread = None
        self.running = False

    def start(self):
        if not self.running:
            self.stop_event.clear()
            self.proxy_thread = threading.Thread(target=run_proxy, args=(self.host, self.http_port, self.https_port, self.stop_event))
            self.proxy_thread.start()
            self.running = True

    def stop(self):
        if self.running:
            self.stop_event.set()
            self.proxy_thread.join()
            self.running = False


def proxy_cli(proxies):
    print("Reverse Proxy Tool v1.0 by Ark")
    print("\nCommands:")
    print("- list: Show all proxies.")
    print("- reload: reload all proxies from the config.ini.")
    print("- start <ID>: Start a specific proxy.")
    print("- start all: Start all proxies.")
    print("- stop <ID>: Stop a specific proxy.")
    print("- stop all: Stop all proxies.")
    print("- status <ID>: Show the status of a specific proxy.")
    print("- status all: Show the status of all proxies.")
    print("- add <Host> <HttpPort> <HttpsPort>: Add a new proxy.")
    print("- edit <ID> <Host> <HttpPort> <HttpsPort>: Edit an existing proxy.")
    print("- delete <ID>: Delete a specific proxy.")
    print("- help: Displays available commands.") 
    print("- exit: Stop all proxies and exit.")  

    while True:
        cmd = input("> ").lower().split()

        if len(cmd) == 0:
            continue

        if cmd[0] == "list":
            for i, proxy in enumerate(proxies, start=1):
                status = "online" if check_port(proxy.host, proxy.http_port) and proxy.running else "offline"
                print(f"Proxy ID: {i}, Host: {proxy.host}, HttpPort: {proxy.http_port}, HttpsPort: {proxy.https_port}, Status: {status}")

        elif cmd[0] == "start":
            if len(cmd) > 1:
                if cmd[1] == "all":
                    for i, proxy in enumerate(proxies, start=1):
                        proxy.start()
                        print(f"Proxy {i} initializing.")
                else:
                    try:
                        proxy_id = int(cmd[1])
                        if 1 <= proxy_id <= len(proxies):
                            proxies[proxy_id - 1].start()
                            print(f"Proxy {proxy_id} initializing.")
                        else:
                            print("Invalid proxy ID.")
                    except ValueError:
                        print("Invalid proxy ID.")
            else:
                print("Usage: start <ID> or start all")


        # Add a new "status" command
        elif cmd[0] == "status":
            if len(cmd) > 1:
                if cmd[1] == "all":
                    for i, proxy in enumerate(proxies, start=1):
                        status = "online" if check_port(proxy.host, proxy.http_port) and proxy.running else "offline"
                        print(f"Proxy ID: {i}, Status: {status}")
                else:
                    try:
                        proxy_id = int(cmd[1])
                        if 1 <= proxy_id <= len(proxies):
                            proxy = proxies[proxy_id - 1]
                            status = "online" if check_port(proxy.host, proxy.http_port) and proxy.running else "offline"
                            print(f"Proxy ID: {proxy_id}, Status: {status}")
                        else:
                            print("Invalid proxy ID.")
                    except ValueError:
                        print("Invalid proxy ID.")
            else:
                print("Usage: status <ID> or status all")


        elif cmd[0] == "stop":
            if len(cmd) > 1:
                if cmd[1] == "all":
                    for i, proxy in enumerate(proxies, start=1):
                        proxy.stop()
                        print(f"Proxy {i} offline.")
                else:
                    try:
                        proxy_id = int(cmd[1])
                        if 1 <= proxy_id <= len(proxies):
                            proxies[proxy_id - 1].stop()
                            print(f"Proxy {proxy_id} offline.")
                        else:
                            print("Invalid proxy ID.")
                    except ValueError:
                        print("Invalid proxy ID.")
            else:
                print("Usage: stop <ID> or stop all")


        elif cmd[0] == "add":
            if len(cmd) == 4:
                host, http_port, https_port = cmd[1], int(cmd[2]), int(cmd[3])
                if not valid_ip(host):
                    print("Invalid IP address.")
                elif not valid_port(http_port) or not valid_port(https_port):
                    print("Invalid port number.")
                elif http_port == https_port:
                    print("HttpPort and HttpsPort cannot be the same.")
                elif ports_in_use(proxies, http_port, https_port):
                    print("One or both of the specified ports are already in use.")
                elif not proxy_exists(proxies, host, http_port, https_port):
                    proxy = Proxy(host, http_port, https_port)
                    proxies.append(proxy)
                    update_config(proxies, config_path)
                    print(f"Added proxy: Host: {host}, HttpPort: {http_port}, HttpsPort: {https_port}")
                else:
                    print("This proxy already exists.")
            else:
                print("Usage: add <Host> <HttpPort> <HttpsPort>")

        elif cmd[0] == "edit":
            if len(cmd) == 5:
                try:
                    proxy_id = int(cmd[1])
                    if 1 <= proxy_id <= len(proxies):
                        if not proxies[proxy_id - 1].running:
                            host, http_port, https_port = cmd[2], int(cmd[3]), int(cmd[4])
                            if not valid_ip(host):
                                print("Invalid IP address.")
                            elif not valid_port(http_port) or not valid_port(https_port):
                                print("Invalid port number.")
                            elif http_port == https_port:
                                print("HttpPort and HttpsPort cannot be the same.")
                            elif ports_in_use(proxies, http_port, https_port, exclude_proxy_id=proxy_id):
                                print("One or both of the specified ports are already in use.")
                            else:
                                print(f"About to edit proxy {proxy_id} with the following details:")
                                print(f"Host: {host}, HttpPort: {http_port}, HttpsPort: {https_port}")
                                while True:
                                    confirm = input("Confirm edit? (yes/no): ").lower()
                                    if confirm == "yes":
                                        proxies[proxy_id - 1].host = host
                                        proxies[proxy_id - 1].http_port = http_port
                                        proxies[proxy_id - 1].https_port = https_port
                                        update_config(proxies, config_path)
                                        print(f"Edited proxy {proxy_id}: Host: {host}, HttpPort: {http_port}, HttpsPort: {https_port}")
                                        break
                                    elif confirm == "no":
                                        print("Edit canceled.")
                                        break
                                    else:
                                        print("Invalid input. Please enter 'yes' or 'no'.")
                        else:
                            print("Cannot edit running threads.")
                    else:
                        print("Invalid proxy ID.")
                except ValueError:
                    print("Invalid proxy ID.")
            else:
                print("Usage: edit <ID> <Host> <HttpPort> <HttpsPort>")
                

        elif cmd[0] == "delete":
            if len(cmd) == 2:
                try:
                    proxy_id = int(cmd[1])
                    if 1 <= proxy_id <= len(proxies):
                        if not proxies[proxy_id - 1].running:
                            while True:
                                print(f"About to delete proxy {proxy_id}")
                                confirm = input("Confirm delete? (yes/no): ").lower()
                                if confirm == "yes":
                                    del proxies[proxy_id - 1]
                                    update_config(proxies, config_path)
                                    print(f"Deleted proxy {proxy_id}")
                                    break
                                elif confirm == "no":
                                    print("Delete canceled.")
                                    break
                                else:
                                    print("Invalid input. Please enter 'yes' or 'no'.")
                        else:
                            print("Cannot delete running threads.")
                    else:
                        print("Invalid proxy ID.")
                except ValueError:
                    print("Invalid proxy ID.")
            else:
                print("Usage: delete <ID>")
                
                
        elif cmd[0] == "reload":
                proxies = reload_configuration(config_path)
                print("Configuration reloaded.")
                                
                                
        elif cmd[0] == "help":
                print("Reverse Proxy Tool v1.0 by Ark")
                print("\nCommands:")
                print("- list: Show all proxies.")
                print("- reload: reload all proxies from the config.ini.")
                print("- start <ID>: Start a specific proxy.")
                print("- start all: Start all proxies.")
                print("- stop <ID>: Stop a specific proxy.")
                print("- stop all: Stop all proxies.")
                print("- status <ID>: Show the status of a specific proxy.")
                print("- status all: Show the status of all proxies.")
                print("- add <Host> <HttpPort> <HttpsPort>: Add a new proxy.")
                print("- edit <ID> <Host> <HttpPort> <HttpsPort>: Edit an existing proxy.")
                print("- delete <ID>: Delete a specific proxy.")
                print("- help: Displays available commands.") 
                print("- exit: Stop all proxies and exit.")                  
                                                                        

        elif cmd[0] == "exit":
            while True:
                confirm = input("Are you sure you want to exit? all thread will be interrupted (yes/no): ").lower()
                if confirm == "yes":
                    break
                elif confirm == "no":
                    print("Exit canceled.")
                    break
                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")

                    
    # Stop all proxies before exiting
    for proxy in proxies:
        proxy.stop()


def ports_in_use(proxies, http_port, https_port, exclude_proxy_id=None):
    for idx, proxy in enumerate(proxies):
        if exclude_proxy_id is not None and idx == exclude_proxy_id - 1:
            continue
        if proxy.http_port == http_port or proxy.https_port == https_port:
            return True
    return False
    
    
def valid_port(port):
    return 1 <= port <= 65535

def valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
        
def reload_configuration(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)

    proxies = []

    for section in config.sections():
        host = config[section]["Host"]
        http_port = int(config[section]["HttpPort"])
        https_port = int(config[section]["HttpsPort"])

        proxy = Proxy(host, http_port, https_port)
        proxies.append(proxy)

    return proxies        
        
def proxy_exists(proxies, host, http_port, https_port):
    for proxy in proxies:
        if proxy.host == host and proxy.http_port == http_port and proxy.https_port == https_port:
            return True
    return False

   
def update_config(proxies, config_path):
    config = configparser.ConfigParser()
    for i, proxy in enumerate(proxies, start=1):
        section = f"Proxy{i}"
        config[section] = {}
        config[section]["Host"] = proxy.host
        config[section]["HttpPort"] = str(proxy.http_port)
        config[section]["HttpsPort"] = str(proxy.https_port)

    with open(config_path, "w") as config_file:
        config.write(config_file)


if __name__ == "__main__":
    config = configparser.ConfigParser()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.ini")
    config.read(config_path)

    proxies = []

    for section in config.sections():
        host = config[section]["Host"]
        http_port = int(config[section]["HttpPort"])
        https_port = int(config[section]["HttpsPort"])

        proxy = Proxy(host, http_port, https_port)
        proxies.append(proxy)

    try:
        # Start a simple command-line interface to control proxies
        proxy_cli(proxies)
    except KeyboardInterrupt:
        print("Shutting down proxies...")

    for proxy in proxies:
        proxy.stop()
