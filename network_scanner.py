# Required imports
import nmap
import socks
import socket
import sys
import random
from scapy.all import ICMP, IP, sr1, TCP, UDP, sr
import concurrent.futures
import re

# Function to get the target network from the user


def get_target_network():
    while True:
        # Prompt the user for input
        network = input("Please enter the target network IP address: ")
        # Validate the IP address using a regex match
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", network):
            return network
        else:
            print("Invalid IP address. Please try again.")


# Initialize nmap scanner
nm = nmap.PortScanner()

# Function to discover hosts in a network


def host_discovery(network):
    try:
        print("Starting host discovery...")
        # Send ICMP requests to the network
        ans, unans = sr(IP(dst=network)/ICMP(), timeout=2, verbose=0)
        print("The following hosts are up:")
        for sent, received in ans:
            # Print the IP address of each host that responded
            print(received.src)
        # Return the list of IP addresses
        return [received.src for sent, received in ans]
    except Exception as e:
        print(f"An error occurred during host discovery: {e}", file=sys.stderr)
        return []

# Function to perform a port scan


def port_scan(host, tor_ip='127.0.0.1', tor_port=9050):
    s = None
    try:
        print(f"Attempting to scan host {host} through Tor...")
        # Initialize a socket using the socks module
        s = socks.socksocket()
        # Set the proxy to Tor
        s.set_proxy(socks.SOCKS5, tor_ip, tor_port)
        # Create a list of ports to scan
        ports = list(range(1, 1025))
        # Randomize the order of the ports
        random.shuffle(ports)
        for port in ports:
            print(f"Scanning port {port}...")
            try:
                # Attempt to connect to the port
                s.connect((host, port))
                print(f"TCP Port {port} is open on {host}")
            except socket.error:
                print("Tor connection failed. Falling back to direct connection...")
                # If the Tor connection fails, use a direct connection
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                for port in ports:
                    print(f"Scanning port {port}...")
                    try:
                        conn = s.connect((host, port))
                        print(f"TCP Port {port} is open on {host}")
                    except socket.error:
                        pass
                break
            except Exception as e:
                print(
                    f"Exception occurred while scanning port {port}: {e}", file=sys.stderr)
            finally:
                # Close the socket
                if s:
                    s.close()
                # Reinitialize the socket
                s = socks.socksocket()
                s.set_proxy(socks.SOCKS5, tor_ip, tor_port)
        # Randomize the order of the ports again for the UDP scan
        random.shuffle(ports)
        for port in ports:
            print(f"Scanning UDP port {port}...")
            # Send a UDP packet to the port
            ans = sr1(IP(dst=host)/UDP(dport=port), timeout=1, verbose=0)
            if ans is None:
                print(f"UDP Port {port} is open on {host}")
    except Exception as e:
        print(f"An error occurred during port scan: {e}", file=sys.stderr)
    finally:
        # Ensure the socket is closed
        if s:
            s.close()

# Function to detect services and their versions


def service_and_version_detection(host):
    try:
        print(f"Starting service and version detection on {host}...")
        # Use nmap to scan the host for services and versions
        nm.scan(host, arguments='-sV --version-intensity 9')
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = nm[host][proto].keys()
                for port in lport:
                    print('port : %s\tstate : %s' %
                          (port, nm[host][proto][port]['state']))
                    service_info = nm[host][proto][port]
                    print(
                        f"Service: {service_info['name']}, Version: {service_info.get('version', 'N/A')}")
    except Exception as e:
        print(
            f"An error occurred during service and version detection: {e}", file=sys.stderr)

# Function to detect the operating system of a host


def os_detection(host):
    try:
        print(f"Starting OS detection on {host}...")
        # Use nmap to scan the host for the operating system
        nm.scan(host, arguments='-O')
        if 'osmatch' in nm[host]:
            for osmatch in nm[host]['osmatch']:
                print('OS: %s; Accuracy: %s' %
                      (osmatch['name'], osmatch['accuracy']))
    except Exception as e:
        print(f"An error occurred during OS detection: {e}", file=sys.stderr)

# Function to perform a firewall evasion and stealth scan


def firewall_evasion_and_stealth_scan(host):
    try:
        print(f"Starting firewall evasion and stealth scan on {host}...")
        # Use nmap to scan the host using firewall evasion and stealth techniques
        nm.scan(host, arguments='-sS -T4 -f -D RND:10')
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
    except Exception as e:
        print(
            f"An error occurred during firewall evasion and stealth scan: {e}", file=sys.stderr)

# Function to perform a vulnerability scan


def vulnerability_scan(host):
    try:
        print(f"Starting vulnerability scan on {host}...")
        # Use nmap to scan the host for vulnerabilities
        nm.scan(host, arguments='--script vuln')
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = nm[host][proto].keys()
                for port in lport:
                    print('Scanning vulnerabilities for port %s' % port)
                    print('port : %s\tstate : %s' %
                          (port, nm[host][proto][port]['state']))
    except Exception as e:
        print(
            f"An error occurred during vulnerability scan: {e}", file=sys.stderr)

# Main function


def main():
    # Get the target network
    network = get_target_network()
    # Discover hosts in the network
    hosts = host_discovery(network)

    # Perform port scans on all discovered hosts
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(port_scan, hosts)

    # List of additional scan functions to perform on each host
    scan_functions = [service_and_version_detection, os_detection,
                      firewall_evasion_and_stealth_scan, vulnerability_scan]
    # Perform additional scans on all discovered hosts
    for scan_func in scan_functions:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(scan_func, hosts)


# If this script is the main module, run the main function
if __name__ == "__main__":
    main()
