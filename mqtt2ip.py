#!/usr/bin/env python

"""
This sample application presents itself as a router between a BACnet/MQTT
and BACnet/IP network.  Note that the length of the B/MQTT address is set
in the bacpypes_mqtt module.  As a router, this does not have an application
layer.
"""

from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.consolelogging import ArgumentParser

from bacpypes.core import run
from bacpypes.comm import bind

from bacpypes.pdu import Address
from bacpypes.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes.bvllservice import BIPSimple, AnnexJCodec, UDPMultiplexer

import bacpypes_mqtt

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
args = None

#
#   MQTT2IPRouter
#


@bacpypes_debugging
class MQTT2IPRouter:
    def __init__(self, lan, mqtt_addr, mqtt_net, ip_addr, ip_net):
        if _debug:
            MQTT2IPRouter._debug(
                "__init__ %r %r %r %r %r", lan, mqtt_addr, mqtt_net, ip_addr, ip_net
            )
        global args

        # a network service access point will be needed
        self.nsap = NetworkServiceAccessPoint()

        # give the NSAP a generic network layer service element
        self.nse = NetworkServiceElement()
        bind(self.nse, self.nsap)

        # == First stack

        # create an MQTT client
        self.s1_msap = bacpypes_mqtt.MQTTClient(
            lan,
            mqtt_addr,
            args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            keepalive=args.keepalive,
        )

        # create a service element for the client
        self.s1_mse = bacpypes_mqtt.MQTTServiceElement()
        bind(self.s1_mse, self.s1_msap)

        # bind to the MQTT network
        self.nsap.bind(self.s1_msap, mqtt_net)

        # == Second stack

        # create a generic BIP stack, bound to the Annex J server
        # on the UDP multiplexer
        self.s2_bip = BIPSimple()
        self.s2_annexj = AnnexJCodec()
        self.s2_mux = UDPMultiplexer(ip_addr)

        # bind the bottom layers
        bind(self.s2_bip, self.s2_annexj, self.s2_mux.annexJ)

        # bind the BIP stack to the local network
        self.nsap.bind(self.s2_bip, ip_net)


#
#   __main__
#


def main():
    global args

    # parse the command line arguments
    parser = ArgumentParser(description=__doc__)

    # arguments for first network
    parser.add_argument("lan", type=str, help="MQTT network name")
    parser.add_argument("mqtt_addr", type=str, help="address on the MQTT network")
    parser.add_argument("mqtt_net", type=int, help="network number of MQTT network")

    # arguments for B/IP network
    parser.add_argument("ip_addr", type=str, help="address on the IPv4 network")
    parser.add_argument("ip_net", type=int, help="network number of IPv4 network")

    # additional options for the MQTT client
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

    # now parse the arguments
    args = parser.parse_args()

    if _debug:
        _log.debug("initialization")
    if _debug:
        _log.debug("    - args: %r", args)

    # create the router
    router = MQTT2IPRouter(
        args.lan,
        Address(args.mqtt_addr),
        args.mqtt_net,
        Address(args.ip_addr),
        args.ip_net,
    )
    if _debug:
        _log.debug("    - router: %r", router)

    # start up the client
    router.s1_mse.startup()

    _log.debug("running")

    run()

    # shutdown the client
    router.s1_mse.shutdown()

    _log.debug("fini")


if __name__ == "__main__":
    main()
