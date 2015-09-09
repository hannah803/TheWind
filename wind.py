#!/usr/bin/env python
# encoding: utf-8

###This is the main framework that accepts connection and launch connections to (ip, port).
###You only need to change the import directive to include your process methods and arguments
###used in this framework. You can refer to forward.py to find out which methods you need to
###implement. And in freak.py you can figure out the implementation of SSL Freak Attack.

###the compulsory arguments you need to supply is ***useOrinAddr*** and ***doProcess***


from handleovpn import *

class ServerHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        global ip, port
        interested = False
        csock = self.request
        if useOrinAddr == True:
            ip, port = get_original_addr(csock)
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.connect((ip, port))
        logging.info("Connecting (%s, %s)"%(ip, port))
        if ip in iplist or port in portlist:
            interested = True
        if not interested:
            while 1:
                try:
                    datalist = recv_one(csock, ssock)
                    for readable, data in datalist:
                        if readable == csock:
                            ssock.sendall(data)
                        else:
                            csock.sendall(data)
                except Exception:
                    pass
            return

        print "\n\nConnecting (%s, %s)"%(ip, port)
        if SSL == True:
            ssl_handler = HandleSSL()
            ssl_handler.process = b_process
        if OPENVPN == True:
            openvpn_handler = HandleOPENVPN()


        try:
            while (1):
                datalist = []
                if SSL == True:
                    datalist = ssl_handler.recv_one(ssock, csock)
                    #if len(datalist) == 0:
                    #    logging.warning("none is readble!")
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
