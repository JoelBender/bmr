#!/usr/bin/python

"""
Utility application that reads in the hex dump traffic from the BMR application
and decodes it.
"""

import sys

from bacpypes.debugging import xtob
from bacpypes.analysis import decode_packet

# read in the file, split into
with open(sys.argv[1]) as infile:
    lines = infile.readlines()
lines = [line[:-1].split("\t") for line in lines]

# dump out the header and the decoded packet
for line in lines:
    pkt = decode_packet(b"\0" * 14 + xtob(line[5]))
    if not pkt:
        pkt_type = "unnable to decode"
    else:
        pkt_type = pkt.__class__.__name__

    print(" ".join(line[:5]) + " ----- " + pkt_type)
    if pkt:
        pkt.debug_contents()
    print("")
