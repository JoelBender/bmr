# BACnet Masquerade Router

The BACnet Masquerade Router (BMR) application is a BACnet router between one
or more BACnet/IPv4 networks and Virtual Local Area Networks (VLAN) of virtual
BACnet devices (VDB).  The virtual devices masquerade as a "digital twin" of
real devices, masking some objects and properties and making others available.

The principle use of this application is to help collect together into one
unified BACnet network a collection of other BACnet intranetworks that have
overlappng BACnet device identifiers and network numbers and therefore cannot
be directly connected.

In some cases these other networks, referred to in this project as "sites",
have developed independantly of each other with no cooperative administration,
or they are "clones" of each other where their was no guidence on making
non-overlapping device identifiers and network numbers.

## Requirements

The applications in this project are based on
[BACpypes](https://github.com/JoelBender/bacpypes), a Python library for the
[BACnet](http://www.bacnet/org) protocol, and
[BACpypes-MQTT](https://github.com/JoelBender/bacpypes-mqtt), an experimental
protocol extension for using MQTT publish/subscribe to emulate a LAN.

For more information see the [wiki](https://github.com/JoelBender/bmr/wiki).

### History and Motivation

Back in the earliest days of the **BACnet Interest Group - North America**, which
is now called [BACnet International](https://www.bacnetinternational.org/),
there was a project called the **Open BACnet Interoperable Wide Area Network**
(OBIWAN) with Dave Thompson, then with the
[The Penn State Facilities Engineering Institute](https://www.psfei.psu.edu/).
The basic idea was simple, allow the BACnet networks in Higher Ed institutions
like Cornell University, Penn State, Ohio State, and Princeton, to join together
into one network that can share real-time data, applications, and insights.

This project is one small component of that overall vision.
