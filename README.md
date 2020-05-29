# PV204 Imrich Nagy & Daniel Rychlý
Repository for PV204 course semestral project @ Faculty of Informatics, Masaryk University

The project consists of analyzing security certificates, then implementing PIN-authenticated secure communication over insecure channel using ephemeral Elliptic Curve Diffie-Hellman protocol and finally, reviewing the implementations of the other teams.

# The Implementation

The implementation consists of Java Card applet and PC Java application, that shows how to establish a secure channel between the PC client and the Java Card (using JCardSim, but the applet is also compilable on real Java Cards). The channel is established using ephemeral ECDH authenticated by PIN.

# IMPORTANT NOTICE!

The implementation is done as a part of school project! It is not tested nor formally verified to provide the security it aims to. It lacks integrity checking and many other functions vital to provide a secure channel suitable for real-world use. The provided scheme is also not resistant to offline bruteforce attacks on the PIN. The applet was not tested on a real smart card, because it had to be developed without access to any real smart card hardware, due to the COVID-19 situation.

# Sources
Card Tools used to connect and communicate with the card were made by Petr Švenda (https://github.com/petrs) and Dušan Klinec (https://github.com/ph4r05). APDU program and the Applet are based on their work as well.

All the functionality is based on Oracle Java documentation and Oracle Java Card framework and documentation.

## Team members
* Danie Rychlý
* Imrich Nagy
