import subprocess
import sys
from termcolor import cprint

COMMANDS = [
    'sysctl -w net.ipv4.ip_forward=1'
]

def run():
    print('Configuring attacker machine as a router ...')
    for c in COMMANDS:
        cprint(f'Executing: {c}', "light_grey", attrs=['dark'])
        command = subprocess.run(c.split(), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        if command.returncode != 0:
            print(f'Error in executing: {c}')
            sys.exit(1)
