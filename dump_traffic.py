#!/usr/bin/python

"""
Utility application that reads in the hex dump traffic from the BMR application
and decodes it.
"""

import sys
import json

from bacpypes.debugging import xtob
from bacpypes.pdu import Address
from bacpypes.analysis import decode_packet

# humph
null_address = Address("0x000000000000")

# read in configuration
with open("xmas-config.json") as bmr_config_file:
    bmr_config = json.load(bmr_config_file)
inside_address = Address(bmr_config["inside"]["_deviceAddress"])
outside_address = Address(bmr_config["outside"]["_deviceAddress"])

# read in the file, split into lines
if len(sys.argv) > 1:
    with open(sys.argv[1]) as infile:
        lines = infile.readlines()
else:
    lines = sys.stdin.readlines()

# strip off eol, split tabs to fields
lines = [line[:-1].split("\t") for line in lines]

# dump out the header and the decoded packet
for indx, line in enumerate(lines):
    timestamp, stack, direction, source, destination, data = line

    pkt = decode_packet(b"\0" * 14 + xtob(data))
    if not pkt:
        pkt_type = "unnable to decode"
    else:
        pkt_type = pkt.__class__.__name__

    if pkt.pduSource == null_address:
        if (direction == ">>>"):
            pkt.pduSource = Address(source)
        elif (direction == "<<<"):
            if (stack == "inside"):
                pkt.pduSource = inside_address
            elif (stack == "outside"):
                pkt.pduSource = outside_address

    if pkt.pduDestination == null_address:
        pkt.pduDestination = Address(destination)

    print(f"{indx+1}. {stack} {direction} {pkt_type}")
    if pkt:
        print("")
        pkt.debug_contents()
    print("")
