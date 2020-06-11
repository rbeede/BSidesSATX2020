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



# Global variables

# key = actual BSSID value
# value = Python dict with 
#					SSID = ssid string or empty string if hidden network
#					CHANNEL = channel number
wireless_access_points = dict()

# Only gets populated if GOOGLE_MAC_PREFIXES matches CLIENT MAC
# keys
# CLIENT MAC
# AP MAC
# CHANNEL
# FREQUENCY
matching_client = dict()

def main(interface):
	print(f"Using wireless device at {interface}")

	worker_rotate_channel = Thread(target=rotate_wifi_channel, args=(interface,), daemon=True)
	worker_rotate_channel.start()

	worker_sniff_wireless = Thread(target=sniff, kwargs={"iface": interface, "prn": packet_handler}, daemon=True)
	worker_sniff_wireless.start()

	print("Waiting to detect a matching client and collecting access points")
	while not matching_client:
		print(".", end="")
		
		time.sleep(1)

	print("FOUND MATCHING CLIENT: ", end="")
	pprint.PrettyPrinter().pprint(matching_client)

	print("Waiting to detect matching AP beacon")
	while not matching_client["AP MAC"] in wireless_access_points:
		print(".", end="")
		
		time.sleep(1)
	
	print("FOUND MATCHING AP: ", end="")
	pprint.PrettyPrinter().pprint(wireless_access_points[matching_client["AP MAC"]])


	# TODO send the deauth

	print("ENDING THE PROGRAM")

	return 0


def packet_handler(pkt):
	if pkt.haslayer(Dot11Beacon):
		bssid = pkt[Dot11].addr2
		ssid = pkt[Dot11Elt].info.decode()
		channel = pkt[Dot11Beacon].network_stats().get("channel")

		# Either adding new entry or always overwritting previous with new data
		wireless_access_points[bssid] = {"SSID": ssid, "CHANNEL": channel}
	elif not matching_client and pkt.haslayer(Dot11) and 2 == pkt[Dot11].type and not pkt.haslayer(EAPOL):
		# We have not matched a client yet
		# We have a data frame (client->AP or AP->client)
		sending_mac = pkt[Dot11].addr2
		receiving_mac = pkt[Dot11].addr1

		frequency = pkt[RadioTap].ChannelFrequency
		if 5 == operator.floordiv(frequency, 1000):
			channel = operator.floordiv(frequency - 5000, 5)
		else:
			channel = operator.floordiv(frequency - 2407, 5)


		if(sending_mac[0:8] in GOOGLE_MAC_PREFIXES):
			matching_client["CLIENT MAC"] = sending_mac
			matching_client["AP MAC"] = receiving_mac
			matching_client["CHANNEL"] = channel
			matching_client["FREQUENCY"] = frequency
		elif(receiving_mac[0:8] in GOOGLE_MAC_PREFIXES):
			matching_client["CLIENT MAC"] = receiving_mac  # switched around
			matching_client["AP MAC"] = sending_mac  # switched around
			matching_client["CHANNEL"] = channel
			matching_client["FREQUENCY"] = frequency


def rotate_wifi_channel(interface):
	curr_channel = 1
	while not matching_client:
		os.system(f"iwconfig {interface} channel {curr_channel}")
		
		#DEBUG, to remove
		curr_channel = curr_channel % 14 + 1
		#curr_channel = 11
		
		time.sleep(2)
	
	# Lock onto the desired channel in-case we are still scanning
	curr_channel = matching_client["CHANNEL"]
	os.system(f"iwconfig {interface} channel {curr_channel}")
	print(f"No longer rotating channel, locked onto {curr_channel}")
	



if "__main__" == __name__:
	parser = argparse.ArgumentParser()
	parser.add_argument("--interface", metavar="wlan0mon", required=True)
	args = parser.parse_args()

	main(**vars(args))
