import argparse
import pyfiglet
from scanner import *

ascii_banner = pyfiglet.figlet_format("Scanity")
print(ascii_banner)


def run_scan(target, args):
    start_time = time.time()
    print(f"Scan started on {start_time}")

    # For storing the specified target ports and inputting them as a list
    ports = []

    if args.specified_target_port:
        # Parse specified ports from the command line input.
        ports = [int(port.strip()) for port in args.specified_target_port.split(',')]

    # Check for the services running in the specified port/ ports
    if args.services_running:
        services = services_running(target, ports)
        if args.verbose:
            print(f"Services running on {target}:")
            for port, service in services.items():
                print(f"Port {port}: {service}")

    # Performing a syn-scan on the target
    elif args.syn_scan:
        open_ports = syn_scan(target, ports)
        if args.verbose:
            print(f"Open SYN ports on {target}: {open_ports}")

    elif args.scan_all_ports:
        # Scanning all ports
        open_ports = scan_all_ports(target)
        if args.verbose:
            print(f"Open TCP ports on {target} (1-65535): {open_ports}")

    elif args.scan_t100:
        # Scanning top 100 known ports
        open_ports = scan_t100(target)
        if args.verbose:
            print(f"Open TCP ports on {target} (Top 100): {open_ports}")

    elif args.scan_t1000:
        # Scanning top 1000 ports
        open_ports = scan_t1000(target)
        if args.verbose:
            print(f"Open TCP ports on {target} (Top 1000): {open_ports}")

    else:
        print("Please specify a scan type using one of the available options.")
        exit(1)

    end_time = time.time()
    print(f"The scanning ended on {end_time}")


def parse_arguments():
    parser = argparse.ArgumentParser(prog='scanity',
                                     description='A basic Python port scanner includes a few essential features that '
                                                 'enable it to function effectively.',
                                     epilog='Remember to follow me at https://github.com/zE0nyx')

    parser.add_argument('t', 'target', required=True, help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', type=str, help='Specify the port range to scan (e.g., "1-100" or "22,80,443")')

    # Arguments for different types of scans
    parser.add_argument('--services_running', action='store_true',
                        help='Scan for running services and their versions on specified ports')
    parser.add_argument('--syn_scan', action='store_true', help='Perform a SYN scan on specified ports')
    parser.add_argument('--specified_target_port', help='Scan specific ports (e.g., 22,80,443)', default=None)
    parser.add_argument('--scan_all_ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('--scan_t100', action='store_true', help='Scan the top 100 most common ports')
    parser.add_argument('--scan_t1000', action='store_true', help='Scan the top 1000 most common ports')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    return parser.parse_args()


def main():
    args = parse_arguments()
    run_scan(args.target, args)


if __name__ == '__main__':
    main()
