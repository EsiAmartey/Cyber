import socket

def scan_ports(target_host, start_port, end_port):
    print(f"Scanning ports on {target_host}...")
    
    # Iterate over the range of ports
    for port in range(start_port, end_port + 1):
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        
        # Try to connect to the port
        result = sock.connect_ex((target_host, port))
        
        # Check if the port is open
        if result == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
        
        # Close the socket
        sock.close()

# Example usage
target_host = "example.com"  # Replace with the target host or IP address
start_port = 1  # Start of the port range to scan
end_port = 100  # End of the port range to scan

scan_ports(target_host, start_port, end_port)
