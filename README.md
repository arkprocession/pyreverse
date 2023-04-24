This script is a reverse proxy server that allows you to forward requests from one web server to another. It is designed to provide a secure way of accessing web applications that are hosted on an internal network, by creating an encrypted connection between the client and the proxy server.

The proxy server can handle HTTP and HTTPS requests, and supports various HTTP methods such as GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, and CONNECT. It also includes error handling to provide informative error messages when things go wrong.

The script includes a command-line interface that allows you to manage multiple proxy instances. You can add, edit, delete, and start/stop proxy servers with this interface.

The script also generates SSL certificates and keys, and allows you to specify the ports for the HTTP and HTTPS connections. Additionally, it provides IP addresses for the hosted instances.

List of commands:

    print("Reverse Proxy Tool v1.0 by Ark")
    print("\nCommands:")
    print("- list: Show all proxies.")
    print("- start <ID>: Start a specific proxy.")
    print("- start all: Start all proxies.")
    print("- stop <ID>: Stop a specific proxy.")
    print("- stop all: Stop all proxies.")
    print("- add <Host> <HttpPort> <HttpsPort>: Add a new proxy.")
    print("- edit <ID> <Host> <HttpPort> <HttpsPort>: Edit an existing proxy.")
    print("- delete <ID>: Delete a specific proxy.")
    print("- exit: Stop all proxies and exit.")
