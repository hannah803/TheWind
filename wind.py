#!/usr/bin/env python
# encoding: utf-8
import select, SocketServer, socket, struct
from scapy.all import *

from header import *

###This is the main framework that accepts connection and launch connections to (ip, port).
###You only need to change the import directive to include your process methods and arguments
###used in this framework. You can refer to forward.py to find out which methods you need to
###implement. And in freak.py you can figure out the implementation of SSL Freak Attack.

###the compulsory arguments you need to supply is ***useOrinAddr*** and ***doProcess***


useOrinAddr = True
SSL = False
#SSL = True
#OPENVPN = False
OPENVPN = True

from handlessl import *
from handleovpn import *

print useOrinAddr

class ServerHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        global ip, port
        csock = self.request
        if useOrinAddr == True:
            ip, port = get_original_addr(csock)
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.connect((ip, port))
        print "Connecting (%s, %s)"%(ip, port)

        if SSL == True:
            ssl_handler = HandleSSL()
        if OPENVPN == True:
            openvpn_handler = HandleOPENVPN()


        try:
            while (1):
                datalist = []
                if SSL == True:
                    datalist = ssl_handler.recv_one(ssock, csock)
                    if len(datalist) == 0:
                        raise ValueError("none is readble!")
                    for readable, data in datalist:
                        if readable == ssock:
                            label = "server"
                        if readable == csock:
                            label = "client"
                        p = TLSRecord(data)
                        assert(str(p) == data)
                        data = str(ssl_handler.handle(p, label))

                        if readable == csock:
                            ssock.sendall(data)
                        else:
                            csock.sendall(data)

                if OPENVPN == True:
                    datalist = openvpn_handler.recv_one(ssock, csock)
                    if len(datalist) == 0:
                        break
                    for readable, data in datalist:
                        if readable == ssock:
                            label = "server"
                        if readable == csock:
                            label = "client"
                        p = OpenVPN(data)
                        assert(str(p) == data)
                        data = str(openvpn_handler.handle(p, label))

                        if readable == csock:
                            ssock.sendall(data)
                        else:
                            csock.sendall(data)
        except socket.error:
            pass
        finally:
            ssock.close()
                            
class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    ThreadedServer.allow_reuse_address = True
    ThreadedServer(('', PORT), ServerHandler).serve_forever()
