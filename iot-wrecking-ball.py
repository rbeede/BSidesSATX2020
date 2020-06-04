#!/usr/bin/env python3

__author__ = "Rodney Beede"
__copyright__ = "Copyright 2020, Rodney Beede"
__license__ = "AGPL Version 3"
__version__ = "1.2020.06.03"


import argparse
import os
import sys
import warnings

import pprint

from scapy.all import *
from threading import Thread


warnings.simplefilter("error")
os.environ["PYTHONWARNINGS"] = "error"


# Constants

# Keep these all *lowercase*
GOOGLE_MAC_PREFIXES = frozenset(['1c:f2:9a',])


# key = actual BSSID value
# value = Python dict with 
#					SSID = ssid string or empty string if hidden network
#					CHANNEL = channel number
wireless_access_points = dict()


def main(interface):
	print(f"Using wireless device at {interface}")

	worker_rotate_channel = Thread(target=rotate_wifi_channel, args=(interface,), daemon=True)
	worker_rotate_channel.start()

	worker_sniff_aps = Thread(target=sniff, kwargs={"iface": interface, "prn": packet_handler}, daemon=True)
	worker_sniff_aps.start()


	while True:
		print("Access Points")
		pprint.PrettyPrinter().pprint(wireless_access_points)
		
		
		time.sleep(1)


	print("ENDING THE PROGRAM")

	return 0


def packet_handler(pkt):
	if pkt.haslayer(Dot11Beacon):
		bssid = pkt[Dot11].addr2
		ssid = pkt[Dot11Elt].info.decode()
		channel = pkt[Dot11Beacon].network_stats().get("channel")
		
		# Either adding new entry or always overwritting previous with new data
		wireless_access_points[bssid] = {"SSID": ssid, "CHANNEL": channel}
	elif pkt.haslayer(Dot11) and 2 == pkt[Dot11].type and not pkt.haslayer(EAPOL):
		# We have a data frame (client->AP or AP->client)
		sending_mac = pkt[Dot11].addr2
		receiving_mac = pkt[Dot11].addr1
		
		if(sending_mac[0:8] in GOOGLE_MAC_PREFIXES):
			print(f"MATCHING Client sent from addr {sending_mac} to AP at {receiving_mac}")
		elif(receiving_mac[0:8] in GOOGLE_MAC_PREFIXES):
			print(f"MATCHING Client received on addr {receiving_mac} from AP at {sending_mac}")
		else:
			print(f"No match between {sending_mac} -> {receiving_mac}")
			
		
def rotate_wifi_channel(interface):
	curr_channel = 1
	while True:
		#os.system(f"iwconfig {interface} channel {curr_channel}")
		
		#curr_channel = curr_channel % 14 + 1
		curr_channel = 11
		
		time.sleep(1)



if "__main__" == __name__:
	parser = argparse.ArgumentParser()
	parser.add_argument("--interface", metavar="wlan0mon", required=True)
	args = parser.parse_args()

	main(**vars(args))
