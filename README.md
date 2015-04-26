TheWind
=============
a MITM attack tool

Aims to do man in the middle attacks on multiple application layer protocols. for now, it only supports SSL protocol.

* Utilize Scapy (http://www.secdev.org/projects/scapy/) to parse packets

* Utilize Scapy-SSL/TLS (https://github.com/tintinweb/scapy-ssl_tls) to support for parsing/building SSL/TLS in Scapy.

Feature
--------
* SSL Freak Attack

Installation
--------
1) mv ssl_tls.py to ./scapy/layers

2) modify ./scapy/config.py to autoload ssl_tls layer
```diff
	config.py::Conf::load_layers 
	375,376c375
	<                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp",
	<                    "ssl_tls", ]
	---
	>                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp"]
 ```

Usage
--------
1. redirect traffic to port 8888: ```iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8888```
or
```rdr on xxiface inet proto tcp from xxx.xxx.xxx.xxx/xx to any port = 443 -> 127.0.0.1 port 8888```
1. edit wind.py to import the right file, for example, add ```import freak``` to launch the SSL FREAK attack
1. you can write your own module to implement a specific ssl attack, the compulsory funtions you need to supply are those in ```forward.py```
1. if man in the middle wants to connect to another server, set ```useOrinAddr = False```, then set ```ip, port```
1. set ```doProcess = True``` to make the process functions take effect
