# -*- coding: utf-8 -*-

"""
BACnet Masqurade Router
"""

import time

from bacpypes.settings import settings as _settings
from bacpypes.debugging import bacpypes_debugging, ModuleLogger, btox
from bacpypes.consolelogging import JSONArgumentParser

from bacpypes.core import run, deferred
from bacpypes.iocb import IOCB

from bacpypes.comm import Client, Server, bind
from bacpypes.pdu import Address, LocalBroadcast

from bacpypes.vlan import Network, Node
from bacpypes.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes.bvllservice import BIPSimple, AnnexJCodec, UDPMultiplexer

from bacpypes.app import Application, ApplicationIOController
from bacpypes.appservice import StateMachineAccessPoint, ApplicationServiceAccessPoint
from bacpypes.local.device import LocalDeviceObject
from bacpypes.service.device import WhoIsIAmServices
from bacpypes.service.object import ReadWritePropertyServices

from bacpypes.primitivedata import CharacterString, ObjectIdentifier
from bacpypes.constructeddata import ArrayOf, Any
from bacpypes.apdu import (
    UnconfirmedRequestPDU,
    SimpleAckPDU,
    ComplexAckPDU,
    WhoIsRequest,
    ReadPropertyRequest,
    ReadPropertyACK,
    ReadPropertyMultipleRequest,
    ReadPropertyMultipleACK,
    WritePropertyRequest,
)

import bacpypes_mqtt

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
args = None
inside_application = None
outside_application = None
debug_traffic_file = None


@bacpypes_debugging
class Debug(Client, Server):
    def __init__(self, label=None, cid=None, sid=None):
        if _debug:
            Debug._debug("__init__ label=%r cid=%r sid=%r", label, cid, sid)

        Client.__init__(self, cid)
        Server.__init__(self, sid)

        # save the label
        self.label = label

    def _now(self):
        now = time.time()
        return time.strftime("%H:%M:%S.", time.gmtime(x)) + "{:03d}".format(
            int((x - int(x)) * 1000)
        )

    def confirmation(self, pdu):
        if debug_traffic_file:
            debug_traffic_file.write(
                f"{self._now()}\t{self.label}\t>>>\t{pdu.pduSource}\t{pdu.pduDestination}\t{btox(pdu.pduData)}\n"
            )

        self.response(pdu)

    def indication(self, pdu):
        if debug_traffic_file:
            timestamp = time.strftime("%H:%M:%S")
            debug_traffic_file.write(
                f"{self._now()}\t{self.label}\t<<<\t{pdu.pduSource}\t{pdu.pduDestination}\t{btox(pdu.pduData)}\n"
            )

        self.request(pdu)


@bacpypes_debugging
class VLANApplication(Application, WhoIsIAmServices, ReadWritePropertyServices):
    def __init__(self, vlan_device, vlan_address, settings):
        if _debug:
            VLANApplication._debug(
                "__init__ %r %r %r", vlan_device, vlan_address, settings
            )
        Application.__init__(self, vlan_device, vlan_address)

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
        self.nsap.bind(self.vlan_node)

        # keep track of the real inside device
        self.proxyAddress = Address(settings["_proxyAddress"])
        self.proxyIdentifier = ("device", settings["_proxyIdentifier"])
        if _debug:
            VLANApplication._debug("    - proxyAddress: %r", self.proxyAddress)
            VLANApplication._debug("    - proxyIdentifier: %r", self.proxyIdentifier)

        # IOCB Context map
        self.iocb_context_map = {}

    def forward_request(self, apdu):
        if _debug:
            VLANApplication._debug(
                "[%s]forward_request %r", self.vlan_node.address, apdu
            )

        # build a key
        iocb_context_key = (apdu.pduSource, apdu.apduInvokeID)

        # check for an existing request, no need to make another
        if iocb_context_key in self.iocb_context_map:
            if _debug:
                VLANApplication._debug("    - existing request")
            return

        # trap read requests of the device object
        if isinstance(apdu, (ReadPropertyRequest, WritePropertyRequest)):
            if apdu.objectIdentifier == self.localDevice.objectIdentifier:
                # trap name and identifier
                if apdu.propertyIdentifier in ("objectName", "objectIdentifier"):
                    if _debug:
                        VLANApplication._debug("    - process locally")
                    Application.indication(self, apdu)
                    return

                if _debug:
                    VLANApplication._debug("    - substitute the proxy device id")
                apdu.objectIdentifier = self.proxyIdentifier
        elif isinstance(apdu, ReadPropertyMultipleRequest):
            for ras in apdu.listOfReadAccessSpecs:
                if ras.objectIdentifier == self.localDevice.objectIdentifier:
                    if _debug:
                        VLANApplication._debug("    - substitute the proxy device id")
                    ras.objectIdentifier = self.proxyIdentifier

        # eliminate the source and invoke ID, rewrite the destination
        apdu.pduSource = apdu.apduInvokeID = None
        apdu.pduDestination = self.proxyAddress
        if _debug:
            VLANApplication._debug("    - apdu: %r", apdu)

        # make an IOCB and reference the context
        iocb = IOCB(apdu)
        iocb.iocb_context = iocb_context_key
        self.iocb_context_map[iocb_context_key] = iocb

        # call us back when it's done
        iocb.add_callback(self.forward_request_complete)

        # pass it along to the inside application to process
        deferred(inside_application.request_io, iocb)

    def forward_request_complete(self, iocb):
        if _debug:
            VLANApplication._debug(
                "[%s]forward_request_complete %r", self.vlan_node.address, iocb
            )

        # extract the context key
        iocb_context_key = iocb.iocb_context

        # check for an error
        if iocb.ioError:
            apdu = iocb.ioError
        elif iocb.ioResponse:
            apdu = iocb.ioResponse
        else:
            VLANApplication._debug("    - invalid IOCB: %r", iocb)
            return
        if _debug:
            VLANApplication._debug("    - apdu: %r", apdu)

        # trap read responses for properties of the device object
        if isinstance(apdu, ReadPropertyACK):
            if apdu.objectIdentifier == self.proxyIdentifier:
                if _debug:
                    VLANApplication._debug("    - substitute our device id")
                apdu.objectIdentifier = self.localDevice.objectIdentifier

                if apdu.propertyIdentifier == "propertyIdentifier":
                    if _debug:
                        VLANApplication._debug(
                            "    - substitute our device id in result"
                        )

                elif apdu.propertyIdentifier == "objectList":
                    if apdu.propertyArrayIndex == 0:
                        if _debug:
                            VLANApplication._debug("    - just array length")

                    elif apdu.propertyArrayIndex is not None:
                        objid = apdu.propertyValue.cast_out(ObjectIdentifier)
                        if _debug:
                            VLANApplication._debug("    - array index value: %r", objid)
                        if objid == self.proxyIdentifier:
                            if _debug:
                                VLANApplication._debug(
                                    "    - substitute our device id in result"
                                )

                    else:
                        object_list = apdu.propertyValue.cast_out(
                            ArrayOf(ObjectIdentifier)
                        )
                        if _debug:
                            VLANApplication._debug(
                                "    - access_result object_list: %r", object_list
                            )
                        for i, objid in enumerate(object_list):
                            if objid == self.proxyIdentifier:
                                if _debug:
                                    VLANApplication._debug(
                                        "    - substitute our device id, index %r", i
                                    )
                                object_list[i] = self.localDevice.objectIdentifier

                                # rebuild the array
                                apdu.propertyValue = Any(
                                    ArrayOf(ObjectIdentifier)(object_list)
                                )
                                break

        elif isinstance(apdu, ReadPropertyMultipleACK):
            for read_access_result in apdu.listOfReadAccessResults:
                # check if this is information from the device object we proxy
                if read_access_result.objectIdentifier != self.proxyIdentifier:
                    continue
                if _debug:
                    VLANApplication._debug("    - substitute our device id")
                read_access_result.objectIdentifier = self.localDevice.objectIdentifier

                for access_result in read_access_result.listOfResults:
                    if access_result.propertyIdentifier == "objectName":
                        if access_result.readResult is not None:
                            objname = access_result.readResult.propertyValue.cast_out(
                                CharacterString
                            )
                            if _debug:
                                VLANApplication._debug(
                                    "    - access_result objname: %r, substitute our name",
                                    objname,
                                )
                            # rebuild the value
                            access_result.readResult.propertyValue = Any(
                                CharacterString(self.localDevice.objectName)
                            )
                    elif access_result.propertyIdentifier == "objectIdentifier":
                        if access_result.readResult is not None:
                            objid = access_result.readResult.propertyValue.cast_out(
                                ObjectIdentifier
                            )
                            if _debug:
                                VLANApplication._debug(
                                    "    - access_result objid: %r, substitute our id",
                                    objid,
                                )
                            # rebuild the value
                            access_result.readResult.propertyValue = Any(
                                ObjectIdentifier(self.localDevice.objectIdentifier)
                            )
                    elif access_result.propertyIdentifier == "objectList":
                        if access_result.readResult is not None:
                            object_list = access_result.readResult.propertyValue.cast_out(
                                ArrayOf(ObjectIdentifier)
                            )
                            if _debug:
                                VLANApplication._debug(
                                    "    - access_result object_list: %r", object_list
                                )
                            for i, objid in enumerate(object_list):
                                if objid == self.proxyIdentifier:
                                    if _debug:
                                        VLANApplication._debug(
                                            "    - substitute our device id"
                                        )
                                    object_list[i] = self.localDevice.objectIdentifier

                                    # rebuild the array
                                    access_result.readResult.propertyValue = Any(
                                        ArrayOf(ObjectIdentifier)(object_list)
                                    )
                                    break

        # eliminate the source, redirect the destination, restore the invoke ID
        apdu.pduSource = None
        apdu.pduDestination = iocb_context_key[0]
        apdu.apduInvokeID = iocb_context_key[1]
        if _debug:
            VLANApplication._debug("    - new apdu: %r", apdu)

        # this is our response
        self.response(apdu)

        # done with this context
        del self.iocb_context_map[iocb_context_key]

    def request(self, apdu):
        if _debug:
            VLANApplication._debug("[%s]request %r", self.vlan_node.address, apdu)
        Application.request(self, apdu)

    def indication(self, apdu):
        if _debug:
            VLANApplication._debug("[%s]indication %r", self.vlan_node.address, apdu)

        # check for some services
        if isinstance(apdu, WhoIsRequest):
            if _debug:
                VLANApplication._debug("    - process locally")
            Application.indication(self, apdu)
            return

        # all other unconfirmed requests dropped
        if isinstance(apdu, UnconfirmedRequestPDU):
            if _debug:
                VLANApplication._debug("    - no forwarding")
            return

        # all other confirmed services are forwarded
        self.forward_request(apdu)

    def response(self, apdu):
        if _debug:
            VLANApplication._debug("[%s]response %r", self.vlan_node.address, apdu)
        Application.response(self, apdu)

    def confirmation(self, apdu):
        if _debug:
            VLANApplication._debug("[%s]confirmation %r", self.vlan_node.address, apdu)
        Application.confirmation(self, apdu)

    def startup(self):
        if _debug:
            VLANApplication._debug("startup")


@bacpypes_debugging
class InsideApplication(
    ApplicationIOController, WhoIsIAmServices, ReadWritePropertyServices
):
    def __init__(self, localDevice, localAddress, deviceInfoCache=None, aseID=None):
        if _debug:
            InsideApplication._debug(
                "__init__ %r %r deviceInfoCache=%r aseID=%r",
                localDevice,
                localAddress,
                deviceInfoCache,
                aseID,
            )
        ApplicationIOController.__init__(
            self, localDevice, localAddress, deviceInfoCache, aseID=aseID
        )

        # local address might be useful for subclasses
        if isinstance(localAddress, Address):
            self.localAddress = localAddress
        else:
            self.localAddress = Address(localAddress)

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

        # create a generic BIP stack, bound to the Annex J server
        # on the UDP multiplexer
        self.bip = BIPSimple()
        self.annexj = AnnexJCodec()
        self.debug = Debug("inside")
        self.mux = UDPMultiplexer(self.localAddress)

        # bind the bottom layers
        bind(self.bip, self.annexj, self.debug, self.mux.annexJ)

        # bind the BIP stack to the network, no network number
        self.nsap.bind(self.bip, address=self.localAddress)

    def request(self, apdu):
        if _debug:
            InsideApplication._debug("request %r", apdu)
        super().request(apdu)

    def indication(self, apdu):
        if _debug:
            InsideApplication._debug("indication %r", apdu)
        super().indication(apdu)

    def response(self, apdu):
        if _debug:
            InsideApplication._debug("response %r", apdu)
        super().response(apdu)

    def confirmation(self, apdu):
        if _debug:
            InsideApplication._debug("confirmation %r", apdu)
        super().confirmation(apdu)

    def close_socket(self):
        if _debug:
            InsideApplication._debug("close_socket")

        # pass to the multiplexer, then down to the sockets
        self.mux.close_socket()


@bacpypes_debugging
class OutsideApplication(Application, WhoIsIAmServices, ReadWritePropertyServices):
    def __init__(self, outside_device, outside_address, settings):
        if _debug:
            OutsideApplication._debug(
                "__init__ %r %r %r", outside_device, outside_address, settings
            )
        Application.__init__(self, outside_device, outside_address)

        # include a application decoder
        self.asap = ApplicationServiceAccessPoint()

        # pass the device object to the state machine access point so it
        # can know if it should support segmentation
        self.smap = StateMachineAccessPoint(outside_device)

        # the segmentation state machines need access to the same device
        # information cache as the application
        self.smap.deviceInfoCache = self.deviceInfoCache

        # a network service access point will be needed
        self.nsap = NetworkServiceAccessPoint()

        # bind the top layers
        bind(self, self.asap, self.smap, self.nsap)

        # give the NSAP a generic network layer service element
        self.nse = NetworkServiceElement()
        bind(self.nse, self.nsap)

        # broker settings
        if "broker" in settings:
            broker_settings = settings["broker"]

            # create an MQTT client
            self.msap = bacpypes_mqtt.MQTTClient(
                broker_settings["lan"],
                outside_address,
                host=broker_settings["host"],
                port=broker_settings["port"],
                username=broker_settings.get("username", None),
                password=broker_settings.get("password", None),
                keepalive=broker_settings["keepalive"],
                cafile=broker_settings.get("cafile", None),
            )

            # create a service element for the client
            self.mse = bacpypes_mqtt.MQTTServiceElement()
            bind(self.mse, self.msap)

            # bind to the MQTT network
            self.nsap.bind(
                self.msap, net=broker_settings["network"], address=outside_address
            )
        # regular IP settings
        else:
            # create a generic BIP stack, bound to the Annex J server
            # on the UDP multiplexer
            self.bip = BIPSimple()
            self.annexj = AnnexJCodec()
            self.debug = Debug("outside")
            self.mux = UDPMultiplexer(outside_address)

            # bind the bottom layers
            bind(self.bip, self.annexj, self.debug, self.mux.annexJ)

            # no special service element
            self.mse = None

            # bind the BIP stack to the network
            self.nsap.bind(
                self.bip, net=settings.outside.network, address=outside_address
            )

        # VLAN settings
        vlan_settings = settings["vlan"]

        # create a VLAN
        self.vlan = Network(broadcast_address=LocalBroadcast())

        # create a node for the router, address 1 on the VLAN
        router_node = Node(Address(1))
        self.vlan.add_node(router_node)

        # bind the router stack to the vlan network through this node
        self.nsap.bind(router_node, net=vlan_settings["network"])

        # make some devices
        for device_settings in vlan_settings["devices"]:
            # make the outside device object
            vlan_device = LocalDeviceObject(**device_settings)
            if _debug:
                OutsideApplication._debug("    - vlan_device: %r", vlan_device)
                OutsideApplication._debug(
                    "    - proxy address: %r", vlan_device._proxyAddress
                )

            # make the VLAN application
            vlan_application = VLANApplication(
                vlan_device, Address(device_settings["_deviceAddress"]), device_settings
            )
            deferred(vlan_application.startup)

            # add it to the network
            self.vlan.add_node(vlan_application.vlan_node)
            if _debug:
                OutsideApplication._debug(
                    "    - vlan_application: %r", vlan_application
                )

    def request(self, apdu):
        if _debug:
            OutsideApplication._debug("request %r", apdu)
        Application.request(self, apdu)

    def indication(self, apdu):
        if _debug:
            OutsideApplication._debug("indication %r", apdu)
        Application.indication(self, apdu)

    def response(self, apdu):
        if _debug:
            OutsideApplication._debug("response %r", apdu)
        Application.response(self, apdu)

    def confirmation(self, apdu):
        if _debug:
            OutsideApplication._debug("confirmation %r", apdu)
        Application.confirmation(self, apdu)


def main():
    global args, inside_application, outside_application, debug_traffic_file

    # parse the command line arguments
    parser = JSONArgumentParser(description=__doc__)

    parser.add_argument("--traffic", type=str, help="debug traffic file")

    # now parse the arguments
    args = parser.parse_args()

    if _debug:
        _log.debug("initialization")
        _log.debug("    - args: %r", args)
        _log.debug("    - _settings: %r", _settings)

    if args.traffic:
        debug_traffic_file = open(args.traffic, "w")

    # settings are the JSON file
    settings = args.json
    if _debug:
        _log.debug("    - settings: %r", settings)

    # make the inside device object
    inside_device = LocalDeviceObject(**settings["inside"])
    if _debug:
        _log.debug("    - inside_device: %r", inside_device)

    # make the inside application
    inside_application = InsideApplication(
        inside_device, Address(settings["inside"]["_deviceAddress"])
    )
    deferred(inside_application.i_am)

    # make the outside device object
    outside_device = LocalDeviceObject(**settings["outside"])
    if _debug:
        _log.debug("    - outside_device: %r", outside_device)

    # make the outside application
    outside_application = OutsideApplication(
        outside_device, Address(settings["outside"]["_deviceAddress"]), settings
    )
    deferred(outside_application.i_am)

    # start up the client
    if outside_application.mse:
        outside_application.mse.startup()

    _log.debug("running")

    run()

    # shutdown the client
    if outside_application.mse:
        outside_application.mse.shutdown()

    if debug_traffic_file:
        debug_traffic_file.close()

    _log.debug("fini")


if __name__ == "__main__":
    main()
