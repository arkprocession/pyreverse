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


def run_proxy(host, http_port, https_port):
    if not check_port(host, http_port):
        print(f"No application running on {host}:{http_port}. Skipping proxy setup.")
        return

    cert_dir = os.path.join("certificates", str(https_port))
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        os.makedirs(cert_dir, exist_ok=True)

        openssl_bin = os.path.join("openssl", "bin", "openssl.exe")
        os.system(f"{openssl_bin} req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj \"/C=US/ST=California/L=San Francisco/O=MyOrg/OU=MyDept/CN=localhost\"")

    HandlerClass = functools.partial(ReverseProxyHTTPRequestHandler, host, http_port)
    httpd = socketserver.TCPServer(("0.0.0.0", https_port), HandlerClass)  # Bind to all interfaces
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    local_ips = get_local_ips()
    public_ip = get_public_ip()

    print(f"Serving HTTPS on the following addresses:")
    for local_ip in local_ips:
        if ':' not in local_ip:  # Filter out IPv6 addresses
            print(f"- https://{local_ip}:{https_port}")
    print(f"- Public IP: https://{public_ip}:{https_port}")



    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read("config.ini")

    proxy_threads = []

    for section in config.sections():
        host = config[section]["Host"]
        http_port = int(config[section]["HttpPort"])
        https_port = int(config[section]["HttpsPort"])

        proxy_thread = threading.Thread(target=run_proxy, args=(host, http_port, https_port))
        proxy_threads.append(proxy_thread)
        proxy_thread.start()

    try:
        for proxy_thread in proxy_threads:
            proxy_thread.join()
    except KeyboardInterrupt:
        print("Shutting down proxies...")