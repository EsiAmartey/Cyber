import socket
import threading
from concurrent.futures import ThreadPoolExecutor

def scan_port(target_host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target_host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except socket.error:
                service = "Unknown"
            print(f"Port {port} is open - Service: {service}")
    except socket.error:
        pass
    finally:
        sock.close()

def scan_ports(target_host, start_port, end_port):
    print(f"Scanning ports on {target_host}...")
    
    with ThreadPoolExecutor() as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target_host, port)

# Example usage
target_host = "example.com"  # Replace with the target host or IP address
start_port = 1  # Start of the port range to scan
end_port = 100  # End of the port range to scan

scan_ports(target_host, start_port, end_port)
