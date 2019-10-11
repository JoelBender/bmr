#!/usr/bin/env python

"""
This application presents a 'console' prompt to the user asking for Who-Is,
I-Am, or Read-Property commands.
"""

import sys

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ConfigArgumentParser
from bacpypes.consolecmd import ConsoleCmd

from bacpypes.comm import bind
from bacpypes.core import run, deferred, enable_sleeping
from bacpypes.iocb import IOCB

from bacpypes.pdu import Address, GlobalBroadcast
from bacpypes.apdu import (
    WhoIsRequest,
    IAmRequest,
    ReadPropertyRequest,
    ReadPropertyACK,
    WritePropertyRequest,
    SimpleAckPDU,
)
from bacpypes.primitivedata import (
    Null,
    Atomic,
    Boolean,
    Unsigned,
    Integer,
    Real,
    Double,
    OctetString,
    CharacterString,
    BitString,
    Date,
    Time,
    ObjectIdentifier,
)
from bacpypes.constructeddata import Array, Any, AnyAtomic


from bacpypes.app import ApplicationIOController
from bacpypes.appservice import StateMachineAccessPoint, ApplicationServiceAccessPoint
from bacpypes.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes.object import get_datatype
from bacpypes.local.device import LocalDeviceObject

# basic services
from bacpypes.service.device import WhoIsIAmServices
from bacpypes.service.object import ReadWritePropertyServices

import bacpypes_mqtt

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
args = None
this_device = None
this_application = None

#
#   MQTTApplication
#


@bacpypes_debugging
class MQTTApplication(
    ApplicationIOController, WhoIsIAmServices, ReadWritePropertyServices
):
    def __init__(
        self, localDevice, lan, localAddress, deviceInfoCache=None, aseID=None
    ):
        if _debug:
            MQTTApplication._debug(
                "__init__ %r %r %r deviceInfoCache=%r aseID=%r",
                localDevice,
                lan,
                localAddress,
                deviceInfoCache,
                aseID,
            )
        ApplicationIOController.__init__(
            self, localDevice, localAddress, deviceInfoCache, aseID=aseID
        )
        global args

        # local address might be useful for subclasses
        if isinstance(localAddress, str):
            localAddress = Address(localAddress)
        if len(localAddress.addrAddr) != bacpypes_mqtt.ADDRESS_LENGTH:
            raise ValueError(
                "local address must be %d octets" % (bacpypes_mqtt.ADDRESS_LENGTH,)
            )

        self.localAddress = localAddress

        # include a application decoder
        self.asap = ApplicationServiceAccessPoint()

        # pass the device object to the state machine access point so it
        # can know if it should support segmentation
        self.smap = StateMachineAccessPoint(localDevice)

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

        # create an MQTT client
        self.msap = bacpypes_mqtt.MQTTClient(
            lan,
            localAddress,
            args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            keepalive=args.keepalive,
            cafile=args.cafile,
        )

        # create a service element for the client
        self.mse = bacpypes_mqtt.MQTTServiceElement()
        bind(self.mse, self.msap)

        # bind the stack to the virtual network, no network number
        self.nsap.bind(self.msap)

        # keep track of requests to line up responses
        self._request = None

    def request(self, apdu):
        if _debug:
            MQTTApplication._debug("request %r", apdu)

        # save a copy of the request
        self._request = apdu

        # forward it along
        super(MQTTApplication, self).request(apdu)

    def indication(self, apdu):
        if _debug:
            MQTTApplication._debug("indication %r", apdu)

        if (isinstance(self._request, WhoIsRequest)) and (isinstance(apdu, IAmRequest)):
            device_type, device_instance = apdu.iAmDeviceIdentifier
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
        super(MQTTApplication, self).indication(apdu)

    def response(self, apdu):
        if _debug:
            MQTTApplication._debug("response %r", apdu)

        # forward it along
        super(MQTTApplication, self).response(apdu)

    def confirmation(self, apdu):
        if _debug:
            MQTTApplication._debug("confirmation %r", apdu)

        # forward it along
        super(MQTTApplication, self).confirmation(apdu)


#
#   ClientConsoleCmd
#


@bacpypes_debugging
class ClientConsoleCmd(ConsoleCmd):
    def do_whois(self, args):
        """whois [ <addr>] [ <lolimit> <hilimit> ]"""
        args = args.split()
        if _debug:
            ClientConsoleCmd._debug("do_whois %r", args)

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
                ClientConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug:
                ClientConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            this_application.request_io(iocb)

        except Exception as err:
            ClientConsoleCmd._exception("exception: %r", err)

    def do_iam(self, args):
        """iam [ addr ]"""
        args = args.split()
        if _debug:
            ClientConsoleCmd._debug("do_iam %r", args)
        global this_device

        try:
            # build a request
            request = IAmRequest()
            if len(args) == 1:
                request.pduDestination = Address(args[0])
            else:
                request.pduDestination = GlobalBroadcast()

            # set the parameters from the device object
            request.iAmDeviceIdentifier = this_device.objectIdentifier
            request.maxAPDULengthAccepted = this_device.maxApduLengthAccepted
            request.segmentationSupported = this_device.segmentationSupported
            request.vendorID = this_device.vendorIdentifier
            if _debug:
                ClientConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug:
                ClientConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            this_application.request_io(iocb)

        except Exception as err:
            ClientConsoleCmd._exception("exception: %r", err)

    def do_read(self, args):
        """read <addr> <type> <inst> <prop> [ <indx> ]"""
        args = args.split()
        if _debug:
            ClientConsoleCmd._debug("do_read %r", args)

        try:
            addr, obj_id, prop_id = args[:3]
            obj_id = ObjectIdentifier(obj_id).value

            datatype = get_datatype(obj_id[0], prop_id)
            if not datatype:
                raise ValueError("invalid property for object type")

            # build a request
            request = ReadPropertyRequest(
                objectIdentifier=obj_id, propertyIdentifier=prop_id
            )
            request.pduDestination = Address(addr)

            if len(args) == 5:
                request.propertyArrayIndex = int(args[4])
            if _debug:
                ClientConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug:
                ClientConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            deferred(this_application.request_io, iocb)

            # wait for it to complete
            iocb.wait()

            # do something for error/reject/abort
            if iocb.ioError:
                sys.stdout.write(str(iocb.ioError) + "\n")

            # do something for success
            elif iocb.ioResponse:
                apdu = iocb.ioResponse

                # should be an ack
                if not isinstance(apdu, ReadPropertyACK):
                    if _debug:
                        ClientConsoleCmd._debug("    - not an ack")
                    return

                # find the datatype
                datatype = get_datatype(
                    apdu.objectIdentifier[0], apdu.propertyIdentifier
                )
                if _debug:
                    ClientConsoleCmd._debug("    - datatype: %r", datatype)
                if not datatype:
                    raise TypeError("unknown datatype")

                # special case for array parts, others are managed by cast_out
                if issubclass(datatype, Array) and (
                    apdu.propertyArrayIndex is not None
                ):
                    if apdu.propertyArrayIndex == 0:
                        value = apdu.propertyValue.cast_out(Unsigned)
                    else:
                        value = apdu.propertyValue.cast_out(datatype.subtype)
                else:
                    value = apdu.propertyValue.cast_out(datatype)
                if _debug:
                    ClientConsoleCmd._debug("    - value: %r", value)

                sys.stdout.write(str(value) + "\n")
                if hasattr(value, "debug_contents"):
                    value.debug_contents(file=sys.stdout)
                sys.stdout.flush()

            # do something with nothing?
            else:
                if _debug:
                    ClientConsoleCmd._debug("    - ioError or ioResponse expected")

        except Exception as error:
            ClientConsoleCmd._exception("exception: %r", error)

    def do_write(self, args):
        """write <addr> <objid> <prop> <value> [ <indx> ] [ <priority> ]"""
        args = args.split()
        ClientConsoleCmd._debug("do_write %r", args)

        try:
            addr, obj_id, prop_id = args[:3]
            obj_id = ObjectIdentifier(obj_id).value
            value = args[3]

            indx = None
            if len(args) >= 5:
                if args[4] != "-":
                    indx = int(args[4])
            if _debug:
                ClientConsoleCmd._debug("    - indx: %r", indx)

            priority = None
            if len(args) >= 6:
                priority = int(args[5])
            if _debug:
                ClientConsoleCmd._debug("    - priority: %r", priority)

            # get the datatype
            datatype = get_datatype(obj_id[0], prop_id)
            if _debug:
                ClientConsoleCmd._debug("    - datatype: %r", datatype)

            # change atomic values into something encodeable, null is a special case
            if value == "null":
                value = Null()
            elif issubclass(datatype, AnyAtomic):
                dtype, dvalue = value.split(":", 1)
                if _debug:
                    ClientConsoleCmd._debug(
                        "    - dtype, dvalue: %r, %r", dtype, dvalue
                    )

                datatype = {
                    "b": Boolean,
                    "u": lambda x: Unsigned(int(x)),
                    "i": lambda x: Integer(int(x)),
                    "r": lambda x: Real(float(x)),
                    "d": lambda x: Double(float(x)),
                    "o": OctetString,
                    "c": CharacterString,
                    "bs": BitString,
                    "date": Date,
                    "time": Time,
                    "id": ObjectIdentifier,
                }[dtype]
                if _debug:
                    ClientConsoleCmd._debug("    - datatype: %r", datatype)

                value = datatype(dvalue)
                if _debug:
                    ClientConsoleCmd._debug("    - value: %r", value)

            elif issubclass(datatype, Atomic):
                if datatype is Integer:
                    value = int(value)
                elif datatype is Real:
                    value = float(value)
                elif datatype is Unsigned:
                    value = int(value)
                value = datatype(value)
            elif issubclass(datatype, Array) and (indx is not None):
                if indx == 0:
                    value = Integer(value)
                elif issubclass(datatype.subtype, Atomic):
                    value = datatype.subtype(value)
                elif not isinstance(value, datatype.subtype):
                    raise TypeError(
                        "invalid result datatype, expecting %s"
                        % (datatype.subtype.__name__,)
                    )
            elif not isinstance(value, datatype):
                raise TypeError(
                    "invalid result datatype, expecting %s" % (datatype.__name__,)
                )
            if _debug:
                ClientConsoleCmd._debug(
                    "    - encodeable value: %r %s", value, type(value)
                )

            # build a request
            request = WritePropertyRequest(
                objectIdentifier=obj_id, propertyIdentifier=prop_id
            )
            request.pduDestination = Address(addr)

            # save the value
            request.propertyValue = Any()
            try:
                request.propertyValue.cast_in(value)
            except Exception as error:
                ClientConsoleCmd._exception("WriteProperty cast error: %r", error)

            # optional array index
            if indx is not None:
                request.propertyArrayIndex = indx

            # optional priority
            if priority is not None:
                request.priority = priority

            if _debug:
                ClientConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug:
                ClientConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            deferred(this_application.request_io, iocb)

            # wait for it to complete
            iocb.wait()

            # do something for success
            if iocb.ioResponse:
                # should be an ack
                if not isinstance(iocb.ioResponse, SimpleAckPDU):
                    if _debug:
                        ClientConsoleCmd._debug("    - not an ack")
                    return

                sys.stdout.write("ack\n")

            # do something for error/reject/abort
            if iocb.ioError:
                sys.stdout.write(str(iocb.ioError) + "\n")

        except Exception as error:
            ClientConsoleCmd._exception("exception: %r", error)

    def do_rtn(self, args):
        """rtn <addr> <net> ... """
        args = args.split()
        if _debug:
            ClientConsoleCmd._debug("do_rtn %r", args)

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

    # build a parser, add some options
    parser = ConfigArgumentParser(description=__doc__)
    parser.add_argument(
        "--lan", type=str, default=bacpypes_mqtt.default_lan_name, help="lan name"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=bacpypes_mqtt.default_broker_host,
        help="broker host address",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=bacpypes_mqtt.default_broker_port,
        help="broker port",
    )
    parser.add_argument("--username", type=str, default=None, help="broker username")
    parser.add_argument("--password", type=str, default=None, help="broker password")
    parser.add_argument(
        "--keepalive",
        type=int,
        default=bacpypes_mqtt.default_broker_keepalive,
        help="maximum period in seconds allowed between communications with the broker",
    )
    parser.add_argument("--cafile", type=str, default=None, help="server certificate")

    # parse the command line arguments
    args = parser.parse_args()

    if _debug:
        _log.debug("initialization")
        _log.debug("    - args: %r", args)

    # make a device object
    this_device = LocalDeviceObject(ini=args.ini)
    if _debug:
        _log.debug("    - this_device: %r", this_device)

    # make a simple application
    this_application = MQTTApplication(this_device, args.lan, args.ini.address)

    # make a console
    this_console = ClientConsoleCmd()
    if _debug:
        _log.debug("    - this_console: %r", this_console)

    # enable sleeping will help with threads
    enable_sleeping()

    # start up the client
    this_application.mse.startup()

    _log.debug("running")

    run()

    # shutdown the client
    this_application.mse.shutdown()

    _log.debug("fini")


if __name__ == "__main__":
    main()
