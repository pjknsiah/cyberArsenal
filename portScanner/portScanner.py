import socket
import sys
from datetime import datetime

def scan_port(target, port, timeout=1):
    """
    Attempt to connect to a specific port on the target.
    Returns True if port is open, False otherwise.
    """
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt to connect to the port
        result = sock.connect_ex((target, port))
        sock.close()
        
        # If result is 0, connection was successful (port is open)
        return result == 0
    except socket.gaierror:
        print(f"Hostname could not be resolved: {target}")
        return False
    except socket.error:
        print(f"Could not connect to server: {target}")
        return False

def get_service_name(port):
    """
    Try to get the common service name for a port.
    """
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def scan_target(target, start_port, end_port):
    """
    Scan a range of ports on the target.
    """
    print("-" * 60)
    print(f"Scanning target: {target}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"Start time: {datetime.now()}")
    print("-" * 60)
    
    open_ports = []
    
    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(target)
        print(f"Resolved {target} to {target_ip}\n")
        
        # Scan each port in the range
        for port in range(start_port, end_port + 1):
            if scan_port(target_ip, port):
                service = get_service_name(port)
                print(f"[+] Port {port} is OPEN - Service: {service}")
                open_ports.append(port)
            else:
                # Optional: uncomment to see closed ports too
                # print(f"[-] Port {port} is closed")
                pass
        
        print("\n" + "-" * 60)
        print(f"Scan completed at {datetime.now()}")
        print(f"Total open ports found: {len(open_ports)}")
        if open_ports:
            print(f"Open ports: {open_ports}")
        print("-" * 60)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit()
    except socket.gaierror:
        print("\nHostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("\nCould not connect to server.")
        sys.exit()

def main():
    """
    Main function to run the port scanner.
    """
    print("\n=== Simple Port Scanner ===\n")
    
    # Get target from user
    target = input("Enter target hostname or IP address (e.g., localhost, 192.168.1.1): ").strip()
    
    if not target:
        print("No target specified. Exiting.")
        return
    
    # Get port range from user
    try:
        start_port = int(input("Enter start port (e.g., 1): ").strip())
        end_port = int(input("Enter end port (e.g., 100): ").strip())
        
        if start_port < 1 or end_port > 65535:
            print("Port numbers must be between 1 and 65535.")
            return
        
        if start_port > end_port:
            print("Start port must be less than or equal to end port.")
            return
        
    except ValueError:
        print("Invalid port number. Please enter integers only.")
        return
    
    # Run the scan
    scan_target(target, start_port, end_port)

if __name__ == "__main__":
    main()