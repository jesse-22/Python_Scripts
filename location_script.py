#!/usr/bin/env python3
"""Sniff IP traffic and show approximate locations for public IP addresses.

Install dependencies with: pip install scapy requests
Run with suitable packet-capture privileges, e.g.:
	sudo python3 location_script.py --interface en0
"""

import argparse
import ipaddress
import time

import requests
from scapy.all import IP, sniff


LOOKUP_CACHE = {}


def lookup_location(address):
	"""Print approximate geolocation information for a public IP address."""
	try:
		parsed = ipaddress.ip_address(address)
	except ValueError:
		return

	if not parsed.is_global or address in LOOKUP_CACHE:
		result = LOOKUP_CACHE.get(address)
		if result is None:
			return
	else:
		try:
			response = requests.get(
				"http://ip-api.com/json/" + address,
				params={"fields": "status,country,regionName,city,lat,lon,isp"},
				timeout=5,
			)
			response.raise_for_status()
			result = response.json()
			LOOKUP_CACHE[address] = result
			time.sleep(0.15)
		except requests.RequestException as error:
			print(f"{address}: lookup failed ({error})")
			return

	if result.get("status") == "success":
		place = ", ".join(
			part for part in (result.get("city"), result.get("regionName"), result.get("country")) if part
		)
		print(
			f"{address}: {place} ({result.get('lat')}, {result.get('lon')})"
			f" | ISP: {result.get('isp', 'unknown')}"
		)


def handle_packet(packet):
	if IP in packet:
		lookup_location(packet[IP].src)
		lookup_location(packet[IP].dst)


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("-i", "--interface", help="interface to sniff")
	parser.add_argument("-c", "--count", type=int, default=0, help="packets to capture; 0 means unlimited")
	args = parser.parse_args()

	print("Sniffing traffic. Press Ctrl-C to stop.")
	sniff(iface=args.interface, prn=handle_packet, store=False, count=args.count)


if __name__ == "__main__":
	main()
