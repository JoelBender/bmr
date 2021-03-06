#!/usr/bin/python

"""
Utility application that reads in the hex dump traffic from the BMR application
and decodes it.

    $ python dump_traffic_read_property_multiple.py config.json dump.txt
"""

import sys
import json

from bacpypes.debugging import xtob
from bacpypes.pdu import Address
from bacpypes.analysis import decode_packet

from bacpypes.primitivedata import Unsigned
from bacpypes.constructeddata import Array, AnyAtomic
from bacpypes.object import get_datatype

from bacpypes.apdu import ReadPropertyMultipleRequest, ReadPropertyMultipleACK, Error


class Traffic:
    def __init__(self, req):
        self.req = req
        self.resp = None
        self.retry = 1


# humph
null_address = Address("0x000000000000")

# read in configuration
with open(sys.argv[1]) as bmr_config_file:
    bmr_config = json.load(bmr_config_file)
inside_address = Address(bmr_config["inside"]["_deviceAddress"])
outside_address = Address(bmr_config["outside"]["_deviceAddress"])

# read in the file, split into lines
with open(sys.argv[2]) as infile:
    lines = infile.readlines()

# strip off eol, split tabs to fields
lines = [line[:-1].split("\t") for line in lines]

traffic = []
requests = {}

# dump out the header and the decoded packet
for indx, line in enumerate(lines):
    timestamp, stack, direction, source, destination, data = line

    pkt = decode_packet(b"\0" * 14 + xtob(data))
    if not pkt:
        pkt_type = "unnable to decode"
    else:
        pkt_type = pkt.__class__.__name__
    pkt._indx = indx + 1

    if pkt.pduSource == null_address:
        if direction == ">>>":
            pkt.pduSource = Address(source)
        elif direction == "<<<":
            if stack == "inside":
                pkt.pduSource = inside_address
            elif stack == "outside":
                pkt.pduSource = outside_address

    if pkt.pduDestination == null_address:
        pkt.pduDestination = Address(destination)

    # check for reads
    if isinstance(pkt, ReadPropertyMultipleRequest):
        key = (pkt.pduSource, pkt.pduDestination, pkt.apduInvokeID)
        if key in requests:
            requests[key].retry += 1
        else:
            msg = Traffic(pkt)
            requests[key] = msg
            traffic.append(msg)

    # now check for results
    elif isinstance(pkt, (ReadPropertyMultipleACK, Error)):
        key = (pkt.pduDestination, pkt.pduSource, pkt.apduInvokeID)
        req = requests.get(key, None)
        if req:
            requests[key].resp = pkt

            # delete the request, it stays in the traffic list
            del requests[key]

# dump everything
for msg in traffic:
    req = msg.req
    resp = msg.resp

    # start with request packet number, source, and destination
    summary = f"{req._indx}/{resp._indx if resp else '*'}\t{req.pduSource}\t{req.pduDestination}"

    if isinstance(resp, Error):
        summary += f"\t{resp.errorClass}/{resp.errorCode}"

    print(summary)
