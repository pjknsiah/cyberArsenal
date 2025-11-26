#!/usr/bin/env python3
"""
Enhanced Port Scanner with Multi-threading and CLI Arguments
Author: [Your Name]
Version: 2.0
"""

import socket
import sys
import argparse
import threading
from datetime import datetime
from queue import Queue
import time

# Thread-safe print lock
print_lock = threading.Lock()

# Global results storage
open_ports = []
scan_progress = {"total": 0, "scanned": 0}


def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Enhanced Multi-threaded Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t localhost -p 1-1000
  %(prog)s -t 192.168.1.1 -p 80,443,8080
  %(prog)s -t example.com -p 1-65535 -T 100 -o results.txt
  %(prog)s -t 10.0.0.1 -p 1-1024 --timeout 2 --verbose
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target hostname or IP address'
    )
    
    parser.add_argument(
        '-p', '--ports',
        required=True,
        help='Port range (e.g., 1-1000) or comma-separated ports (e.g., 80,443,8080)'
    )
    
    parser.add_argument(
        '-T', '--threads',
        type=int,
        default=50,
        help='Number of threads (default: 50)'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Connection timeout in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for results'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output (show closed ports)'
    )
    
    parser.add_argument(
        '--progress',
        action='store_true',
        help='Show progress indicator'
    )
    
    parser.add_argument(
        '--banner',
        action='store_true',
        help='Attempt to grab service banners'
    )
    
    return parser.parse_args()


def parse_ports(port_string):
    """
    Parse port string into a list of ports.
    Supports ranges (1-100) and comma-separated values (80,443,8080).
    """
    ports = []
    
    try:
        # Split by comma for multiple ranges/ports
        parts = port_string.split(',')
        
        for part in parts:
            part = part.strip()
            
            # Check if it's a range
            if '-' in part:
                start, end = part.split('-')
                start, end = int(start.strip()), int(end.strip())
                
                if start < 1 or end > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                if start > end:
                    raise ValueError("Start port must be less than or equal to end port")
                
                ports.extend(range(start, end + 1))
            else:
                # Single port
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                ports.append(port)
        
        return sorted(set(ports))  # Remove duplicates and sort
    
    except ValueError as e:
        print(f"Error parsing ports: {e}")
        sys.exit(1)


def grab_banner(sock, timeout=2):
    """
    Attempt to grab service banner from an open port.
    """
    try:
        sock.settimeout(timeout)
        # Send a generic request
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner[:100] if banner else None  # Limit banner length
    except:
        return None


def scan_port(target_ip, port, timeout, grab_banner_flag=False):
    """
    Scan a single port on the target.
    Returns tuple: (port, is_open, service_name, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((target_ip, port))
        
        service_name = "Unknown"
        banner = None
        
        if result == 0:
            # Port is open
            try:
                service_name = socket.getservbyport(port)
            except:
                pass
            
            if grab_banner_flag:
                banner = grab_banner(sock, timeout)
            
            sock.close()
            return (port, True, service_name, banner)
        else:
            sock.close()
            return (port, False, None, None)
    
    except socket.error:
        return (port, False, None, None)


def worker(target_ip, port_queue, timeout, verbose, grab_banner_flag):
    """
    Worker thread function that processes ports from the queue.
    """
    global open_ports, scan_progress
    
    while True:
        try:
            port = port_queue.get(timeout=1)
        except:
            break
        
        port, is_open, service, banner = scan_port(target_ip, port, timeout, grab_banner_flag)
        
        with print_lock:
            scan_progress["scanned"] += 1
            
            if is_open:
                open_ports.append(port)
                output = f"[+] Port {port:5d} is OPEN"
                if service != "Unknown":
                    output += f" - Service: {service}"
                if banner:
                    output += f" - Banner: {banner}"
                print(output)
            elif verbose:
                print(f"[-] Port {port:5d} is closed")
        
        port_queue.task_done()


def progress_indicator(port_queue, total_ports):
    """
    Display progress indicator in a separate thread.
    """
    global scan_progress
    
    while scan_progress["scanned"] < total_ports:
        scanned = scan_progress["scanned"]
        percentage = (scanned / total_ports) * 100
        
        # Simple progress bar
        bar_length = 40
        filled = int(bar_length * scanned / total_ports)
        bar = '█' * filled + '-' * (bar_length - filled)
        
        sys.stdout.write(f'\r[{bar}] {percentage:.1f}% ({scanned}/{total_ports} ports)')
        sys.stdout.flush()
        
        time.sleep(0.5)
    
    sys.stdout.write('\n')
    sys.stdout.flush()


def save_results(filename, target, open_ports_list, start_time, end_time):
    """
    Save scan results to a file.
    """
    try:
        with open(filename, 'w') as f:
            f.write(f"Port Scan Results\n")
            f.write(f"=" * 60 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan started: {start_time}\n")
            f.write(f"Scan completed: {end_time}\n")
            f.write(f"Duration: {end_time - start_time}\n")
            f.write(f"Total open ports: {len(open_ports_list)}\n")
            f.write(f"\nOpen Ports:\n")
            f.write("-" * 60 + "\n")
            
            for port in sorted(open_ports_list):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                f.write(f"Port {port:5d} - {service}\n")
            
            f.write("=" * 60 + "\n")
        
        print(f"\n[*] Results saved to: {filename}")
    except Exception as e:
        print(f"\n[!] Error saving results: {e}")


def main():
    """
    Main function to orchestrate the port scanning.
    """
    global open_ports, scan_progress
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Banner
    print("\n" + "=" * 60)
    print("Enhanced Multi-threaded Port Scanner v2.0")
    print("=" * 60)
    
    # Parse ports
    ports_to_scan = parse_ports(args.ports)
    total_ports = len(ports_to_scan)
    scan_progress["total"] = total_ports
    
    # Resolve target
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"\nTarget: {args.target}")
        if args.target != target_ip:
            print(f"Resolved to: {target_ip}")
    except socket.gaierror:
        print(f"\n[!] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)
    
    print(f"Ports to scan: {total_ports}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout}s")
    if args.banner:
        print("Banner grabbing: Enabled")
    print(f"\nScan started: {datetime.now()}")
    print("-" * 60)
    
    start_time = datetime.now()
    
    # Create port queue
    port_queue = Queue()
    for port in ports_to_scan:
        port_queue.put(port)
    
    # Start progress indicator if requested
    if args.progress:
        progress_thread = threading.Thread(
            target=progress_indicator,
            args=(port_queue, total_ports),
            daemon=True
        )
        progress_thread.start()
    
    # Create and start worker threads
    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(
            target=worker,
            args=(target_ip, port_queue, args.timeout, args.verbose, args.banner),
            daemon=True
        )
        thread.start()
        threads.append(thread)
    
    # Wait for all tasks to complete
    port_queue.join()
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    # Print summary
    print("-" * 60)
    print(f"\nScan completed: {end_time}")
    print(f"Duration: {duration}")
    print(f"Total open ports found: {len(open_ports)}")
    
    if open_ports:
        print(f"Open ports: {sorted(open_ports)}")
    else:
        print("No open ports found.")
    
    print("=" * 60 + "\n")
    
    # Save results if output file specified
    if args.output:
        save_results(args.output, args.target, open_ports, start_time, end_time)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)