#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
import argparse
import subprocess
from colorama import init, Fore		# for fancy/colorful display

class ARPspoof_Detector:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.Cyan = Fore.CYAN
        self.Yellow = Fore.YELLOW
        self.RESET = Fore.RESET

    def arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--interface', dest='interface', help='Specify The Interface')
        value = parser.parse_args()
        if not value.interface:
            parser.error('\n{}[-] Please Specify The Queue Number {}'.format(self.GREEN, self.RESET))
        return value

    def get_mac(self, ip):
        packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.ARP(pdst=ip)
        ans = scapy.srp(packet, timeout=1, verbose=False)[0]
        if ans:
            return ans[0][1].hwsrc

    def process_packets(self, packet):
        if packet.haslayer(scapy.ARP):      # can combine at once
            if packet[scapy.ARP].op == 2:    # we check for the ARP response (op=2)
                try:
                    real_mac = self.get_mac(packet[scapy.ARP].psrc)
                    response_mac = packet[scapy.ARP].hwsrc

                    if real_mac != response_mac:
                        print("{}[!] You are under attack !{}".format(self.RED, self.RESET))
                except IndexError:
                    pass

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_packets)

    def start(self):
        option = self.arguments()
        subprocess.call(['clear'])

        print('{}\n\n\t\t\t\t\t\t#########################################################{}'.format(self.Cyan, self.RESET))
        print('\n{}\t\t\t\t\t\t#\t      Detecting A R P Spoofing Attack\t\t#\n{}'.format(self.Cyan, self.RESET))
        print('{}\t\t\t\t\t\t#########################################################{}\n\n'.format(self.Cyan, self.RESET))

        print('\n\n{}[+] Detecting Attack ...{}\n'.format(self.Yellow, self.RESET))
        self.sniff(option.interface)

if __name__ == "__main__":
    obj = ARPspoof_Detector()
    obj.start()