# Scanity

Scanity is a simple and efficient network scanner built in Python. It allows users to discover hosts and services on a network, making it an essential tool for network administrators, security professionals, and anyone interested in network exploration.

## Features

- Discover live hosts on a network.
- Scan for open ports on specified hosts.
- Identify services running on open ports.
- Easy-to-use command-line interface.

## Requirements

- Python 3.7 or higher
- Scapy library

## Installation

To install Scanity, clone the repository and install the required dependencies:

```bash
git clone https://github.com/yourusername/scanity.git
cd scanity
pip install .
```

Alternatively, you can install it directly from PyPI (if published):
```bash
pip install scanity
```

## Usage
After installation, you can use Scanity from the command line, check for the usage of the python tool by using the ```--help``` command
```bash
scanity [options] 
```
## Options

```-t, --target <target>```: Specify the target IP address or hostname to scan.

```-p, --ports <port_range>```: Specify the port range to scan (e.g., 1-65535).

```-h, --help```: Show help message and exit.

```--services_running```: Scan for running services and their versions on specified ports

```--syn_scan```: Perform a SYN scan on specified ports

```--specified_target_port```: Scan specific ports (e.g., 22,80,443)

```--scan_all_ports```: Scan all 65535 ports

```--scan_t100```: Scan the top 100 most common ports

```--scan_t1000```: Scan the top 1000 most common ports

```-v, --verbose```: Enable verbose output

## Example
To scan a specific target for open ports:
```scanity --target 192.168.1.1 --ports 1-100```
or 
```sudo python3 ./scanity --target 192.168.1.1 --ports 1-100```

## Contributing
Contributions are welcome! If you'd like to contribute, please fork the repository and create a pull request.

## License
This project is not officially licensed. Feel free to use it as you see fit.

# Author
Arghya Bala
iamze0onyx@gmail.com

    


