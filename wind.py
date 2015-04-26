#!/usr/bin/env python
# encoding: utf-8
import select, SocketServer, socket, struct
from scapy.all import *
from ssl_tls_crypto import TLSSessionCtx
from header import *


###This is the main framework that accepts connection and launch connections to (ip, port).
###You only need to change the import directive to include your process methods and arguments
###used in this framework. You can refer to forward.py to find out which methods you need to
###implement. And in freak.py you can figure out the implementation of SSL Freak Attack.

###the compulsory arguments you need to supply is ***useOrinAddr*** and ***doProcess***


useOrinAddr = True
doProcess = False

#from freak import *
from forward import *


class ServerHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        self.clientfinished = False
        self.serverfinished = False

        csock = self.request
        if useOrinAddr == True:
            ip, port = get_original_addr(csock)
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.connect((ip, port))
        print "Connecting (%s, %s)"%(ip, port)
        self.csession = TLSSessionCtx()
        self.ssession = TLSSessionCtx()

        try:
            while (1):
                datalist = recv_one(ssock, csock)
                if len(datalist) == 0:
                    break
                for readable, data in datalist:
                    p = TLSRecord(data)
                    #print data.encode('hex')
                    #print str(p).encode('hex')
                    if not doProcess:
                        if readable == csock:
                            ssock.sendall(str(p))
                        else:
                            csock.sendall(str(p))
                        continue
                    assert(str(p) == data)
                    content_type = p.content_type 
                    if readable == csock:
                        label = 'client'
                    else:
                        label = 'server'
                    
                    if content_type == HANDSHAKE:
                        p = self.processHandshake(p, label)
                    elif content_type == CHANGE_CIPHER_SPEC:
                        assert(p.length == 1)
                        assert(p.message == '\x01')
                        if readable == csock:
                            print "CLIENT_CHANGE_CIPHER_SPEC"
                            self.clientfinished = True
                        else:
                            print "SERVER_CHANGE_CIPHER_SPEC"
                            self.serverfinished = True
                    elif content_type == ALERT:
                        print "ALERT"
                    elif content_type == APPLICATION_DATA:
                        print '-'*80
                        print '-'*29 + 'APPLICATION_DATA BEGIN' + '-'*29
                        print '-'*80
                        if readable == csock:
                            p = clientappdataprocess(self.csession, self.ssession, p)
                        if readable == ssock:
                            p = serverappdataprocess(self.csession, self.ssession, p)
                        print '-'*80
                        print '-'*29 + 'APPLICATION_DATA END' + '-'*29
                        print '-'*80

                    if readable == csock:
                        ssock.sendall(str(p))
                    else:
                        csock.sendall(str(p))
        except socket.error:
            pass
        finally:
            ssock.close()
                            
    def processHandshake(self, p, label):
        hs_type = ord(str(p)[5])  #hacks here
        if hs_type == HELLO_REQUEST:
            print "HELLO_REQUEST"
        elif hs_type == CLIENT_HELLO and not (self.clientfinished or self.serverfinished):
            print "CLIENT_HELLO"
            self.csession.cumulatedmsg += str(p)[5:]
            self.csession.process(p)
            p = clienthelloprocess(self.csession, self.ssession, p)
            self.ssession.cumulatedmsg += str(p)[5:]
            self.ssession.process(p)
        elif hs_type == SERVER_HELLO and not (self.clientfinished or self.serverfinished):
            print "SERVER_HELLO"
            self.ssession.cumulatedmsg += str(p)[5:]
            self.ssession.process(p)
            p = serverhelloprocess(self.csession, self.ssession, p)
            self.csession.cumulatedmsg += str(p)[5:]
            self.csession.process(p)
        elif hs_type == CERTIFICATE and not (self.clientfinished or self.serverfinished):
            print "CERTIFICATE"
            self.csession.cumulatedmsg += str(p)[5:]
            self.csession.process(p)
            p = certificateprocess(self.csession, self.ssession, p)
            self.ssession.cumulatedmsg += str(p)[5:]
            self.ssession.process(p)
        elif hs_type == SERVER_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
            print "SERVER_KEY_EXCHANGE"
            self.ssession.cumulatedmsg += str(p)[5:]
            self.ssession.process(p)
            p = serverkeyexgprocess(self.csession, self.ssession, p)
            self.csession.cumulatedmsg += str(p)[5:]
            self.csession.process(p)
        elif hs_type == CERTIFICATE_REQUEST:
            print "CERTIFICATE_REQUEST"
        elif hs_type == SERVER_HELLO_DONE and not (self.clientfinished or self.serverfinished):
            print "SERVER_HELLO_DONE"
            self.csession.cumulatedmsg += str(p)[5:]
            self.csession.process(p)
            self.ssession.process(p)
            self.ssession.cumulatedmsg += str(p)[5:]
        elif hs_type == CERTIFICATE_VERIFY:
            print "CERTIFICATE_VERIFY"
        elif hs_type == CLIENT_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
            print "CLIENT_KEY_EXCHANGE"
            self.csession.cumulatedmsg += str(p)[5:]
            self.csession.process(p)
            p = clientkeyexgprocess(self.csession, self.ssession, p)
            self.ssession.cumulatedmsg += str(p)[5:]
            self.ssession.process(p)
        elif hs_type == CERTIFICATE_STATUS:
            print "CERTIFICATE_STATUS"
        else:
            if label == 'client' and self.clientfinished:
                print "CLIENT_ENCRYPTED_HS_MSG"
                print str(p).encode('hex')
                print p.show()
                p = clientfinishprocess(self.csession, self.ssession, p)
            elif label == 'server' and self.serverfinished:
                print "SERVER_ENCRYPTED_HS_MSG"
                print str(p).encode('hex')
                print p.show()
                p = serverfinishprocess(self.csession, self.ssession, p)
            else:
                print 'label:', label, self.clientfinished, self.serverfinished
                print "error!!!!not handshake message!!"
                #print self.postprocess(data).encode('hex')
        return p


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    ThreadedServer.allow_reuse_address = True
    ThreadedServer(('', PORT), ServerHandler).serve_forever()
