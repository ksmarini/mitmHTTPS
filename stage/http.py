from http.server import SimpleHTTPRequestHandler, HTTPServer
from termcolor import cprint
from scapy.arch import conf


def run(interface):
    HTTP_PORT = 80
    ATTACKER_IP = conf.ifaces[interface].ip

    cprint('*** HTTP server running ***', 'magenta', attrs=['blink', 'reverse'])

    httpd = HTTPServer((ATTACKER_IP, HTTP_PORT), SimpleHTTPRequestHandler)
    httpd.serve_forever()