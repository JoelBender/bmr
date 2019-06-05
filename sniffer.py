#!/usr/bin/env python

"""
This application listens for traffic on a BACnet/MQTT network by subscribing
to the entire network topic family and decodes each of the packets it
receives.
"""

import sys

from bacpypes.debugging import bacpypes_debugging, ModuleLogger, btox
from bacpypes.consolelogging import ArgumentParser
from bacpypes.core import run, enable_sleeping

from bacpypes.pdu import LocalBroadcast, PDU
from bacpypes.npdu import NPDU, npdu_types
from bacpypes.apdu import (
    APDU,
    apdu_types,
    confirmed_request_types,
    unconfirmed_request_types,
    complex_ack_types,
    error_types,
    ConfirmedRequestPDU,
    UnconfirmedRequestPDU,
    SimpleAckPDU,
    ComplexAckPDU,
    SegmentAckPDU,
    ErrorPDU,
    RejectPDU,
    AbortPDU,
)

import paho.mqtt.client as _paho_mqtt

from bacpypes_mqtt import (
    BROADCAST_TOPIC,
    topic2addr,
    default_lan_name,
    default_broker_host,
    default_broker_port,
    default_broker_keepalive,
    BVLPDU,
    bvl_pdu_types,
    EncapsulatedNPDU,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
args = None

#
#   decode_packet
#


@bacpypes_debugging
def decode_packet(data, destination):
    """decode the data, return some kind of PDU."""
    if _debug:
        decode_packet._debug("decode_packet %r %r", data, destination)

    # build a PDU
    pdu = PDU(data, destination=destination)

    # decode the BVLCI header
    xpdu = BVLPDU()
    xpdu.decode(pdu)
    pdu = xpdu

    # make a more focused interpretation
    atype = bvl_pdu_types.get(pdu.bvlciFunction)
    if not atype:
        if _debug:
            decode_packet._debug("    - unknown BVLL type: %r", pdu.bvlciFunction)
        return pdu
    if _debug:
        decode_packet._debug("    - atype: %r", atype)

    # decode it as one of the basic types
    try:
        xpdu = pdu
        bpdu = atype()
        bpdu.decode(pdu)
        if _debug:
            decode_packet._debug("    - bpdu: %r", bpdu)

        pdu = bpdu

        # source address in the packet
        pdu.pduSource = pdu.bvlciAddress

        # no deeper decoding for some
        if atype != EncapsulatedNPDU:
            return pdu

    except Exception as err:
        if _debug:
            decode_packet._debug("    - %r decoding error: %r", atype, err)
        return xpdu

    # check for version number (Python2.7 hack)
    if pdu.pduData[0] not in ("\1", 0x01):
        if _debug:
            decode_packet._debug(
                "    - not a version 1 packet: %s...", btox(pdu.pduData[:30], ".")
            )
        return None

    # it's an NPDU
    try:
        npdu = NPDU()
        npdu.decode(pdu)
    except Exception as err:
        if _debug:
            decode_packet._debug("    - NPUD decoding error: %r", err)
        return None

    # application or network layer message
    if npdu.npduNetMessage is None:
        if _debug:
            decode_packet._debug("    - not a network layer message, try as an APDU")

        # decode as a generic APDU
        try:
            xpdu = APDU()
            xpdu.decode(npdu)
            apdu = xpdu
        except Exception as err:
            if _debug:
                decode_packet._debug("    - APDU decoding error: %r", err)
            return npdu

        # "lift" the source and destination address
        if npdu.npduSADR:
            apdu.pduSource = npdu.npduSADR
        else:
            apdu.pduSource = npdu.pduSource
        if npdu.npduDADR:
            apdu.pduDestination = npdu.npduDADR
        else:
            apdu.pduDestination = npdu.pduDestination

        # make a more focused interpretation
        atype = apdu_types.get(apdu.apduType)
        if not atype:
            if _debug:
                decode_packet._debug("    - unknown APDU type: %r", apdu.apduType)
            return apdu

        # decode it as one of the basic types
        try:
            xpdu = apdu
            apdu = atype()
            apdu.decode(xpdu)
        except Exception as err:
            if _debug:
                decode_packet._debug("    - %r decoding Error: %r", atype, err)
            return xpdu

        # decode it at the next level
        if isinstance(apdu, ConfirmedRequestPDU):
            atype = confirmed_request_types.get(apdu.apduService)
            if not atype:
                if _debug:
                    decode_packet._debug(
                        "    - no confirmed request decoder: %r", apdu.apduService
                    )
                return apdu

        elif isinstance(apdu, UnconfirmedRequestPDU):
            atype = unconfirmed_request_types.get(apdu.apduService)
            if not atype:
                if _debug:
                    decode_packet._debug(
                        "    - no unconfirmed request decoder: %r", apdu.apduService
                    )
                return apdu

        elif isinstance(apdu, SimpleAckPDU):
            atype = None

        elif isinstance(apdu, ComplexAckPDU):
            atype = complex_ack_types.get(apdu.apduService)
            if not atype:
                if _debug:
                    decode_packet._debug(
                        "    - no complex ack decoder: %r", apdu.apduService
                    )
                return apdu

        elif isinstance(apdu, SegmentAckPDU):
            atype = None

        elif isinstance(apdu, ErrorPDU):
            atype = error_types.get(apdu.apduService)
            if not atype:
                if _debug:
                    decode_packet._debug("    - no error decoder: %r", apdu.apduService)
                return apdu

        elif isinstance(apdu, RejectPDU):
            atype = None

        elif isinstance(apdu, AbortPDU):
            atype = None
        if _debug:
            decode_packet._debug("    - atype: %r", atype)

        # deeper decoding
        try:
            if atype:
                xpdu = apdu
                apdu = atype()
                apdu.decode(xpdu)
        except Exception as err:
            if _debug:
                decode_packet._debug("    - %r decoding error: %r", atype, err)
            return xpdu

        # success
        return apdu

    else:
        # make a more focused interpretation
        ntype = npdu_types.get(npdu.npduNetMessage)
        if not ntype:
            if _debug:
                decode_packet._debug(
                    "    - no network layer decoder: %r", npdu.npduNetMessage
                )
            return npdu
        if _debug:
            decode_packet._debug("    - ntype: %r", ntype)

        # deeper decoding
        try:
            xpdu = npdu
            npdu = ntype()
            npdu.decode(xpdu)
        except Exception as err:
            if _debug:
                decode_packet._debug("    - %r decoding error: %r", ntype, err)
            return xpdu

        # success
        return npdu


#
#   MQTTSniffer
#
#   This class is a mapping between the client/server pattern and the
#   MQTT API.
#


@bacpypes_debugging
class MQTTSniffer:
    def __init__(
        self,
        lan,
        host=default_broker_host,
        port=default_broker_port,
        keepalive=default_broker_keepalive,
    ):
        if _debug:
            MQTTSniffer._debug("__init__ %r %r %r %r", lan, host, port, keepalive)

        # save the lan
        self.lan = lan

        # save the connection parameters
        self.host = host
        self.port = port
        self.keepalive = keepalive

        # create a client and set the callbacks
        self.mqtt_client = _paho_mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.on_subscribe = self.on_subscribe
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_publish = self.on_publish
        self.mqtt_client.on_unsubscribe = self.on_unsubscribe

        # we are not connected
        self.mqtt_connected = False

    def startup(self):
        if _debug:
            MQTTSniffer._debug("startup")

        # queue up a start the connection process
        response = self.mqtt_client.connect(self.host, self.port, self.keepalive)
        if _debug:
            MQTTSniffer._debug("    - connect: %r", response)

        result, mid = self.mqtt_client.subscribe(self.lan + "/#", qos=1)
        if _debug:
            MQTTSniffer._debug("    - subscribe result, mid: %r, %r", result, mid)

        # start the client loop
        response = self.mqtt_client.loop_start()
        if _debug:
            MQTTSniffer._debug("    - loop_start: %r", response)

    def shutdown(self):
        if _debug:
            MQTTSniffer._debug("shutdown")

        # stop listening
        result, mid = self.mqtt_client.unsubscribe(self.lan + "/#")
        if _debug:
            MQTTSniffer._debug(
                "    - broadcast unsubscribe result, mid: %r, %r", result, mid
            )

        # disconnect
        response = self.mqtt_client.disconnect()
        if _debug:
            MQTTSniffer._debug("    - disconnect: %r", response)

        # stop the client loop
        response = self.mqtt_client.loop_stop()
        if _debug:
            MQTTSniffer._debug("    - loop_stop: %r", response)

    def on_connect(self, client, userdata, flags, rc):
        """Callback for when the client receives a CONNACK response from the server.
        """
        if _debug:
            MQTTSniffer._debug("on_connect %r %r %r %r", client, userdata, flags, rc)

        # we are connected
        self.mqtt_connected = True

    def on_disconnect(self, *args):
        if _debug:
            MQTTSniffer._debug("on_disconnect %r", args)

        # we are no longer connected
        self.mqtt_connected = False

    def on_subscribe(self, client, userdata, mid, granted_qos):
        if _debug:
            MQTTSniffer._debug(
                "on_subscribe %r %r %r %r", client, userdata, mid, granted_qos
            )

    def on_message(self, client, userdata, msg):
        """Callback for when a PUBLISH message is received from the server.
        """
        if _debug:
            MQTTSniffer._debug("on_message ...")
        if _debug:
            MQTTSniffer._debug("    - msg.topic: %r", msg.topic)
        if _debug:
            MQTTSniffer._debug("    - payload: %r", btox(msg.payload))

        topic_address = msg.topic.split("/")[-1]
        if _debug:
            MQTTSniffer._debug("    - topic_address: %r", topic_address)

        # make destination a little more abstact
        if topic_address == BROADCAST_TOPIC:
            topic_address = LocalBroadcast()
        else:
            topic_address = topic2addr(topic_address)

        packet_data = decode_packet(msg.payload, topic_address)
        print(packet_data)
        packet_data.debug_contents(file=sys.stdout)

    def on_publish(self, client, userdata, mid):
        """Callback for when the data is published."""
        if _debug:
            MQTTSniffer._debug("on_publish ...")

    def on_unsubscribe(self, client, userdata, mid):
        if _debug:
            MQTTSniffer._debug("on_unsubscribe ...")


#
#   __main__
#


def main():
    global args, this_device, this_application

    # build a parser, add some options
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--lan", type=str, default=default_lan_name, help="lan name")
    parser.add_argument(
        "--host", type=str, default=default_broker_host, help="broker host address"
    )
    parser.add_argument(
        "--port", type=int, default=default_broker_port, help="broker port"
    )
    parser.add_argument(
        "--keepalive",
        type=int,
        default=default_broker_keepalive,
        help="maximum period in seconds allowed between communications with the broker",
    )

    # parse the command line arguments
    args = parser.parse_args()

    if _debug:
        _log.debug("initialization")
        _log.debug("    - args: %r", args)

    # make a simple application
    this_application = MQTTSniffer(args.lan, args.host, args.port, args.keepalive)

    # enable sleeping will help with threads
    enable_sleeping()

    # start up the client
    this_application.startup()

    _log.debug("running")

    run()

    # shutdown the client
    this_application.shutdown()

    _log.debug("fini")


if __name__ == "__main__":
    main()
