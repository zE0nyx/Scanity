from socket import *
from scapy.layers.inet import *
from ports import *

# s = socket(AF_INET, SOCK_STREAM)
# start = time
# end = time


# Service running on the port
def ServicesRunning(target_ip, target_ports):
    print("[*] Services running")
    services = {}
    for port in target_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            if banner:
                services[port] = banner
                print(f"[+]Port {port} - Service: {banner}")
            else:
                print(f"[-] Port {port} - No banner detected.")
        except socket.timeout:
            print(f"[-] Port {port} - No banner (timeout).")
        except Exception as e:
            print(f"[-] Port {port} - Error: {e}")

    return services


# Range-based scanning
# def RangeScanning(ipaddress, s_port, l_port):
#     print(f"[*] Scanning the range {s_port} to {l_port}")


# Syn Scanning the host
def syn_scan(target_ip, target_ports):
    print(f"[*] Scanning for the Open Ports in {target_ip}")
    open_ports = []
    try:
        for port in target_ports:
            syn_packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
            response = sr1(syn_packet, timeout=1, verbose=0)

            if response is None:
                print(f"Port {port} is filtered or unresponsive.")

            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                # SYN-ACK received (0x12 is the SYN-ACK flag)
                open_ports.append(port)
                print(f"Port {port} is open.")

                # Send RST to gracefully close the open connection
                sr(IP(dst=target_ip) / TCP(dport=port, flags='R'), timeout=1, verbose=0)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:

                # RST received (0x14 is the RST flag)
                print(f"Port {port} is closed.")
            else:
                print(f"Port {port} is in an unknown state.")

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.")

    except socket.gaierror:
        print("\n[*] Hostname could not be resolved.")

    except socket.error:
        print("\n[*] Couldn't connect to server.")

    except Exception as e:
        print(f"\n[*] An error occurred: {e}")

    # return open_ports


# User defined target
def SpecificTargetPort(target_ip, target_ports):
    print("[*] Scanning Initiated")
    open_ports = []

    try:
        for port in target_ports:
            s = socket(AF_INET, SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect((target_ip, target_ports))
            if result == 0:
                open_ports.append(port)
            s.close()
        if not open_ports:
            print("[-] Port is either closed or filtered.\n")
        else:
            for i in open_ports:
                print(f"[+] Port {i} is Open\n")

    except KeyboardInterrupt:
        print("\n [*] Exiting the Program.")

    except socket.gaierror:
        print("\n [*] Hostname could not be resolved.")

    except socket.error:
        print("\n [*] Server not responding !!!!")

    except Exception as e:
        print(f"An error occurred: {e}")


# Scanning for all the Ports
def scan_all_ports(ipaddress):
    print("[*] Scanning all the ports from 1-65535\n")
    open_ports = []

    # Checking if the connection is possible
    try:
        for port in range(1, 65535):
            s = socket(AF_INET, SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect((ipaddress, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        if not open_ports:
            print("[-] All ports are closed or filtered\n")
        else:
            for i in open_ports:
                print(f"[+] Port {i} is Open\n")

    # Few common exceptions
    except KeyboardInterrupt:
        print("\n [*] Exiting the Program.")

    except socket.gaierror:
        print("\n [*] Hostname could not be resolved.")

    except socket.error:
        print("\n [*] Server not responding !!!!")

    except Exception as e:
        print(f"\nAn error occurred: {e}")


# Scanning top 1000 ports:
def ScanT1000(ipaddress):
    print("[*] Scanning all the 1000 ports.")
    open_ports = []
    try:
        for port in top_1000_ports:
            s = socket(AF_INET, SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect((ipaddress, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        if not open_ports:
            print("[-] Ports are either closed or filtered\n")
        else:
            for i in open_ports:
                print(f"[*] The port {i} is Open\n")

    except KeyboardInterrupt:
        print("\n [*] Exiting the Program.")

    except socket.gaierror:
        print("\n Hostname could not be resolved.")

    except socket.error:
        print("\n Server not responding !!!!")

    except Exception as e:
        print(f"An error occurred: {e}")


# Scanning the top 100 ports:
def ScanT100(ipaddress):
    print("[*] Scanning all the 100 ports")
    open_ports = []

    try:
        for port in top_100_ports:
            s = socket(AF_INET, SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect((ipaddress, port))
            if result == 0:
                open_ports.append(port)
            s.close()

        if not open_ports:
            print("[-] Ports are either closed or filtered")
        else:
            for i in open_ports:
                print(f"[*] The port {i} is Open")

    except KeyboardInterrupt:
        print("\n [*] Exiting the Program.")

    except socket.gaierror:
        print("\n Hostname could not be resolved.")

    except socket.error:
        print("\n Server not responding !!!!")

    except Exception as e:
        print(f"An error occurred: {e}")
