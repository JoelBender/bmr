#!/usr/bin/env python

"""
VLAN Router

$ python WhoIsIAMVLAN.py <net1> <addr1> <net2> <addr2> ( <addr> <devid> )...

This application is similer to the one with the same name in the BACpypes
project.  It presents itself as a router to a VLAN with one or more
devices on it, the first device will have an attached console that can send
and receive Who-Is and I-Am messages.

BACnet address net1:addr1 is the BACnet/IP address, net2:addr2 is the address
of the router on the VLAN, the first device will be at net2:addr with a device
instance devid.
"""

import sys
import argparse

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ArgumentParser
from bacpypes.consolecmd import ConsoleCmd

from bacpypes.comm import bind
from bacpypes.core import run, deferred
from bacpypes.iocb import IOCB

from bacpypes.pdu import Address, LocalBroadcast, GlobalBroadcast
from bacpypes.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes.bvllservice import BIPSimple, AnnexJCodec, UDPMultiplexer

from bacpypes.app import ApplicationIOController
from bacpypes.appservice import StateMachineAccessPoint, ApplicationServiceAccessPoint
from bacpypes.local.device import LocalDeviceObject
from bacpypes.service.device import WhoIsIAmServices
from bacpypes.service.object import (
    ReadWritePropertyServices,
    ReadWritePropertyMultipleServices,
)
from bacpypes.apdu import WhoIsRequest, IAmRequest
from bacpypes.errors import DecodingError

from bacpypes.vlan import Network, Node

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
args = None
this_device = None
this_application = None

#
#   VLANApplication
#


@bacpypes_debugging
class VLANApplication(
    ApplicationIOController,
    WhoIsIAmServices,
    ReadWritePropertyServices,
    ReadWritePropertyMultipleServices,
):
    def __init__(self, vlan_device, vlan_address, aseID=None):
        if _debug:
            VLANApplication._debug(
                "__init__ %r %r aseID=%r", vlan_device, vlan_address, aseID
            )
        ApplicationIOController.__init__(self, vlan_device, vlan_address, aseID=aseID)

        # include a application decoder
        self.asap = ApplicationServiceAccessPoint()

        # pass the device object to the state machine access point so it
        # can know if it should support segmentation
        self.smap = StateMachineAccessPoint(vlan_device)

        # the segmentation state machines need access to the same device
        # information cache as the application
        self.smap.deviceInfoCache = self.deviceInfoCache

        # a network service access point will be needed
        self.nsap = NetworkServiceAccessPoint()

        # give the NSAP a generic network layer service element
        self.nse = NetworkServiceElement()
        bind(self.nse, self.nsap)

        # bind the top layers
        bind(self, self.asap, self.smap, self.nsap)

        # create a vlan node at the assigned address
        self.vlan_node = Node(vlan_address)

        # bind the stack to the node, no network number
        self.nsap.bind(self.vlan_node, address=vlan_address)

        # keep track of requests to line up responses
        self._request = None

        if _debug:
            VLANApplication._debug(
                "    - nsap.local_address: %r", self.nsap.local_address
            )

    def request(self, apdu):
        if _debug:
            VLANApplication._debug("request %r", apdu)
        if _debug:
            VLANApplication._debug(
                "    - nsap.local_address: %r", self.nsap.local_address
            )

        # save a copy of the request
        self._request = apdu

        # forward it along
        super(VLANApplication, self).request(apdu)

    def indication(self, apdu):
        if _debug:
            VLANApplication._debug("indication %r", apdu)

        if (isinstance(self._request, WhoIsRequest)) and (isinstance(apdu, IAmRequest)):
            device_type, device_instance = apdu.iAmDeviceIdentifier
            if device_type != "device":
                raise DecodingError("invalid object type")

            if (self._request.deviceInstanceRangeLowLimit is not None) and (
                device_instance < self._request.deviceInstanceRangeLowLimit
            ):
                pass
            elif (self._request.deviceInstanceRangeHighLimit is not None) and (
                device_instance > self._request.deviceInstanceRangeHighLimit
            ):
                pass
            else:
                # print out the contents
                sys.stdout.write("pduSource = " + repr(apdu.pduSource) + "\n")
                sys.stdout.write(
                    "iAmDeviceIdentifier = " + str(apdu.iAmDeviceIdentifier) + "\n"
                )
                sys.stdout.write(
                    "maxAPDULengthAccepted = " + str(apdu.maxAPDULengthAccepted) + "\n"
                )
                sys.stdout.write(
                    "segmentationSupported = " + str(apdu.segmentationSupported) + "\n"
                )
                sys.stdout.write("vendorID = " + str(apdu.vendorID) + "\n")
                sys.stdout.flush()

        # forward it along
        super(VLANApplication, self).indication(apdu)

    def response(self, apdu):
        if _debug:
            VLANApplication._debug("[%s]response %r", self.vlan_node.address, apdu)
        super(VLANApplication, self).response(apdu)

    def confirmation(self, apdu):
        if _debug:
            VLANApplication._debug("[%s]confirmation %r", self.vlan_node.address, apdu)
        super(VLANApplication, self).confirmation(apdu)


#
#   VLANRouter
#


@bacpypes_debugging
class VLANRouter:
    def __init__(self, local_address, local_network):
        if _debug:
            VLANRouter._debug("__init__ %r %r", local_address, local_network)

        # a network service access point will be needed
        self.nsap = NetworkServiceAccessPoint()

        # give the NSAP a generic network layer service element
        self.nse = NetworkServiceElement()
        bind(self.nse, self.nsap)

        # create a BIPSimple, bound to the Annex J server
        # on the UDP multiplexer
        self.bip = BIPSimple(local_address)
        self.annexj = AnnexJCodec()
        self.mux = UDPMultiplexer(local_address)

        # bind the bottom layers
        bind(self.bip, self.annexj, self.mux.annexJ)

        # bind the BIP stack to the local network
        self.nsap.bind(self.bip, local_network, local_address)


#
#   WhoIsIAmConsoleCmd
#


@bacpypes_debugging
class WhoIsIAmConsoleCmd(ConsoleCmd):
    def do_whois(self, args):
        """whois [ <addr>] [ <lolimit> <hilimit> ]"""
        args = args.split()
        if _debug:
            WhoIsIAmConsoleCmd._debug("do_whois %r", args)

        try:
            # build a request
            request = WhoIsRequest()
            if (len(args) == 1) or (len(args) == 3):
                request.pduDestination = Address(args[0])
                del args[0]
            else:
                request.pduDestination = GlobalBroadcast()

            if len(args) == 2:
                request.deviceInstanceRangeLowLimit = int(args[0])
                request.deviceInstanceRangeHighLimit = int(args[1])
            if _debug:
                WhoIsIAmConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug:
                WhoIsIAmConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            this_application.request_io(iocb)

        except Exception as err:
            WhoIsIAmConsoleCmd._exception("exception: %r", err)

    def do_iam(self, args):
        """iam"""
        args = args.split()
        if _debug:
            WhoIsIAmConsoleCmd._debug("do_iam %r", args)

        try:
            # build a request
            request = IAmRequest()
            request.pduDestination = GlobalBroadcast()

            # set the parameters from the device object
            request.iAmDeviceIdentifier = this_device.objectIdentifier
            request.maxAPDULengthAccepted = this_device.maxApduLengthAccepted
            request.segmentationSupported = this_device.segmentationSupported
            request.vendorID = this_device.vendorIdentifier
            if _debug:
                WhoIsIAmConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug:
                WhoIsIAmConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            this_application.request_io(iocb)

        except Exception as err:
            WhoIsIAmConsoleCmd._exception("exception: %r", err)

    def do_rtn(self, args):
        """rtn <addr> <net> ... """
        args = args.split()
        if _debug:
            WhoIsIAmConsoleCmd._debug("do_rtn %r", args)

        # provide the address and a list of network numbers
        router_address = Address(args[0])
        network_list = [int(arg) for arg in args[1:]]

        # pass along to the service access point
        this_application.nsap.add_router_references(None, router_address, network_list)


#
#   __main__
#


def main():
    global args, this_device, this_application

    # parse the command line arguments
    parser = ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # add an argument for interval
    parser.add_argument("net1", type=int, help="network number of IPv4 network")

    # add an argument for interval
    parser.add_argument("addr1", type=str, help="address on the IPv4 network")

    # add an argument for interval
    parser.add_argument("net2", type=int, help="network number of VLAN network")

    # add an argument for interval
    parser.add_argument("addr2", type=str, help="router address on the VLAN network")

    # pull in the extra arguments
    parser.add_argument(
        "xargs",
        metavar="N",
        type=str,
        nargs="+",
        help="address and device identifier for VLAN device",
    )

    # now parse the arguments
    args = parser.parse_args()

    if _debug:
        _log.debug("initialization")
    if _debug:
        _log.debug("    - args: %r", args)

    local_network = args.net1
    local_address = Address(args.addr1)
    if _debug:
        _log.debug(
            "    - local_network, local_address: %r, %r", local_network, local_address
        )

    vlan_network = args.net2
    vlan_address = Address(args.addr2)
    if _debug:
        _log.debug(
            "    - vlan_network, vlan_address: %r, %r", vlan_network, vlan_address
        )

    # create the VLAN router, bind it to the local network
    router = VLANRouter(local_address, local_network)

    # create a VLAN
    vlan = Network(broadcast_address=LocalBroadcast())

    # create a node for the router, address 1 on the VLAN
    router_node = Node(Address(1))
    vlan.add_node(router_node)

    # bind the router stack to the vlan network through this node
    router.nsap.bind(router_node, vlan_network)

    # send network topology
    deferred(router.nse.i_am_router_to_network)

    while args.xargs:
        vlan_address = Address(args.xargs.pop(0))
        vlan_devid = int(args.xargs.pop(0))
        if _debug:
            _log.debug(
                "    - vlan_address, vlan_devid: %r, %r", vlan_address, vlan_devid
            )

        # make a vlan device object
        vlan_device = LocalDeviceObject(
            objectName="VLAN {}".format(vlan_devid),
            objectIdentifier=("device", vlan_devid),
            maxApduLengthAccepted=1024,
            segmentationSupported="noSegmentation",
            vendorIdentifier=15,
        )
        _log.debug("    - this_device: %r", this_device)

        # make the application, add it to the network
        vlan_application = VLANApplication(vlan_device, vlan_address)
        vlan.add_node(vlan_application.vlan_node)
        _log.debug("    - vlan_application: %r", vlan_application)

        if not this_application:
            this_device = vlan_device
            this_application = vlan_application

    # make a console
    this_console = WhoIsIAmConsoleCmd()
    if _debug:
        _log.debug("    - this_console: %r", this_console)

    _log.debug("running")

    run()

    _log.debug("fini")


if __name__ == "__main__":
    main()
