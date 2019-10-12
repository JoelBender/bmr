# -*- coding: utf-8 -*-

"""
BACnet Masqurade Router
"""

from bacpypes.settings import settings as _settings
from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import JSONArgumentParser

from bacpypes.core import run, deferred
from bacpypes.iocb import IOCB

from bacpypes.comm import bind
from bacpypes.pdu import Address, LocalBroadcast

from bacpypes.vlan import Network, Node
from bacpypes.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes.bvllservice import BIPSimple, AnnexJCodec, UDPMultiplexer

from bacpypes.app import Application, BIPSimpleApplication
from bacpypes.appservice import StateMachineAccessPoint, ApplicationServiceAccessPoint
from bacpypes.local.device import LocalDeviceObject
from bacpypes.service.device import WhoIsIAmServices
from bacpypes.service.object import ReadWritePropertyServices

from bacpypes.primitivedata import ObjectIdentifier
from bacpypes.constructeddata import ArrayOf, Any
from bacpypes.apdu import (
    UnconfirmedRequestPDU,
    SimpleAckPDU,
    ComplexAckPDU,
    ErrorPDU,
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

        # eliminate the source and invoke ID, rewrite the destination
        apdu.pduSource = apdu.apduInvokeID = None
        apdu.pduDestination = self.proxyAddress
        if _debug:
            VLANApplication._debug("    - apdu: %r", apdu)

        # trap read requests of the device object for its identifier
        if isinstance(apdu, (ReadPropertyRequest, WritePropertyRequest)):
            if apdu.objectIdentifier == self.localDevice.objectIdentifier:
                if apdu.propertyIdentifier == "objectIdentifier":
                    if _debug:
                        VLANApplication._debug("    - process locally")
                    Application.indication(self, apdu)
                    return
                else:
                    if _debug:
                        VLANApplication._debug("    - substitute the proxy device id")
                    apdu.objectIdentifier = self.proxyIdentifier
        elif isinstance(apdu, ReadPropertyMultipleRequest):
            for ras in apdu.listOfReadAccessSpecs:
                if ras.objectIdentifier == self.localDevice.objectIdentifier:
                    if _debug:
                        VLANApplication._debug("    - substitute the proxy device id")
                    ras.objectIdentifier = self.proxyIdentifier

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
            if isinstance(iocb.ioError, (SimpleAckPDU, ComplexAckPDU, ErrorPDU)):
                apdu = iocb.ioError
            else:
                VLANApplication._debug("    - abort/reject: %r", iocb.ioError)
                return
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
        elif isinstance(apdu, ReadPropertyMultipleACK):
            for read_access_result in apdu.listOfReadAccessResults:
                if read_access_result.objectIdentifier == self.proxyIdentifier:
                    if _debug:
                        VLANApplication._debug("    - substitute our device id")
                    read_access_result.objectIdentifier = (
                        self.localDevice.objectIdentifier
                    )
                for access_result in read_access_result.listOfResults:
                    if access_result.propertyIdentifier == "objectIdentifier":
                        if access_result.readResult is not None:
                            objid = access_result.readResult.propertyValue.cast_out(
                                ObjectIdentifier
                            )
                            if _debug:
                                VLANApplication._debug(
                                    "    - access_result objid: %r", objid
                                )
                            if objid == self.proxyIdentifier:
                                if _debug:
                                    VLANApplication._debug(
                                        "    - substitute our device id"
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
    BIPSimpleApplication, WhoIsIAmServices, ReadWritePropertyServices
):
    def __init__(self, inside_device, inside_address):
        if _debug:
            InsideApplication._debug("__init__ %r %r", inside_device, inside_address)
        BIPSimpleApplication.__init__(self, inside_device, inside_address)

    def request(self, apdu):
        if _debug:
            InsideApplication._debug("request %r", apdu)
        BIPSimpleApplication.request(self, apdu)

    def indication(self, apdu):
        if _debug:
            InsideApplication._debug("indication %r", apdu)
        BIPSimpleApplication.indication(self, apdu)

    def response(self, apdu):
        if _debug:
            InsideApplication._debug("response %r", apdu)
        BIPSimpleApplication.response(self, apdu)

    def confirmation(self, apdu):
        if _debug:
            InsideApplication._debug("confirmation %r", apdu)
        BIPSimpleApplication.confirmation(self, apdu)


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
            self.mux = UDPMultiplexer(outside_address)

            # bind the bottom layers
            bind(self.bip, self.annexj, self.mux.annexJ)

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
    global args, inside_application, outside_application

    # parse the command line arguments
    parser = JSONArgumentParser(description=__doc__)

    # now parse the arguments
    args = parser.parse_args()

    if _debug:
        _log.debug("initialization")
        _log.debug("    - args: %r", args)
        _log.debug("    - _settings: %r", _settings)

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

    _log.debug("fini")


if __name__ == "__main__":
    main()
