import pyfiglet
import socket
import argparse
import time
from scanner import *

ascii_banner = pyfiglet.figlet_format("Scanity")
print(ascii_banner)


# Take inputs from argument parser
target = input("What do you want to scan")

def Scanning(command):
    print(f"[*] Starting the scan on the target host: {command}")
    pass


def main():
    parser = argparse.ArgumentParser(prog='scanity',
                                    description='A basic Python port scanner includes a few essential features that '
                                                'enable it to function effectively.',
                                    epilog='Remember to follow me at https://github.com/zE0nyx')

    args = parser.parse_args(target)
    Scanning(args)



if __name__ == '__main__':
    main()
