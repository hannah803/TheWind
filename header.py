#!/usr/bin/env python
#encoding: utf-8

import socket, struct, sys, subprocess
PORT = 8888
SO_ORIGINAL_DST = 80


def lookup(address, port, s):
    """
        Parse the pfctl state output s, to look up the destination host
        matching the client (address, port).

        Returns an (address, port) tuple, or None.
    """
    spec = "%s:%s" % (address, port)
    for i in s.split("\n"):
        if "ESTABLISHED:ESTABLISHED" in i and spec in i:
            s = i.split()
            if len(s) > 4:
                if sys.platform == "freebsd10":
                    # strip parentheses for FreeBSD pfctl
                    s = s[3][1:-1].split(":")
                else:
                    s = s[4].split(":")

                if len(s) == 2:
                    return s[0], int(s[1])
    raise RuntimeError("Could not resolve original destination.")

def get_original_addr(csock):
    output = subprocess.check_output("uname")
    if not output.strip() == "Linux":
        address, port = csock.getpeername()
        s = subprocess.check_output(("sudo", "-n", "/sbin/pfctl", "-s", "state"), stderr=subprocess.STDOUT)
        return lookup(address, port, s)
    odestdata = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
    address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
    return address, port
