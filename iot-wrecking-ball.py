#!/usr/bin/env python3

__author__ = "Rob Knight, Gavin Huttley, and Peter Maxwell"
__copyright__ = "Copyright 2007, The Cogent Project"
__license__ = "AGPL Version 3"
__version__ = "1.2020.05.27"


import argparse
import os
import sys
import warnings


warnings.simplefilter('error')
os.environ['PYTHONWARNINGS'] = 'error'



def main(interface):
	print(f'Using wireless device at {interface}')

	return 0


if '__main__' == __name__:
	parser = argparse.ArgumentParser()
	parser.add_argument('--interface', metavar='wlan0', required=True)
	args = parser.parse_args()

	main(**vars(args))
