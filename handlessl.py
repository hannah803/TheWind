from ssl_tls_crypto import TLSSessionCtx
import socket, select, struct

#from freak import *
from forward import *
#from messageFraud import *

CHANGE_CIPHER_SPEC = 20
ALERT = 21
HANDSHAKE = 22
APPLICATION_DATA = 23

HELLO_REQUEST = 0
CLIENT_HELLO = 1
SERVER_HELLO = 2
CERTIFICATE = 11
SERVER_KEY_EXCHANGE = 12
CERTIFICATE_REQUEST = 13
SERVER_HELLO_DONE = 14
CERTIFICATE_VERIFY = 15
CLIENT_KEY_EXCHANGE = 16
FINISHED = 20
CERTIFICATE_STATUS = 22

class HandleSSL:
    clientfinished = False
    serverfinished = False
    csession = TLSSessionCtx()
    ssession = TLSSessionCtx()

    def handle(self, p, label):
        content_type = p.content_type
        if content_type == HANDSHAKE:
            p = self.processHandshake(p, label)
        elif content_type == CHANGE_CIPHER_SPEC:
            assert(p.length == 1)
            assert(p.message == '\x01')
            if label == "client":
                print "CLIENT_CHANGE_CIPHER_SPEC"
                self.clientfinished = True
            if label == "server":
                print "SERVER_CHANGE_CIPHER_SPEC"
                self.serverfinished = True
        elif content_type == ALERT:
            print "ALERT"
        elif content_type == APPLICATION_DATA:
            print '-'*80
            print '-'*29 + 'APPLICATION_DATA BEGIN' + '-'*29
            print '-'*80
            if label == "client":
                p = clientappdataprocess(self.csession, self.ssession, p)
            if label == "server":
                p = serverappdataprocess(self.csession, self.ssession, p)
            print '-'*80
            print '-'*29 + 'APPLICATION_DATA END' + '-'*29
            print '-'*80
        return p

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
                #print str(p).encode('hex')
                #print p.show()
                p = clientfinishprocess(self.csession, self.ssession, p)
            elif label == 'server' and self.serverfinished:
                print "SERVER_ENCRYPTED_HS_MSG"
                #print str(p).encode('hex')
                #print p.show()
                p = serverfinishprocess(self.csession, self.ssession, p)
            else:
                print 'label:', label, self.clientfinished, self.serverfinished
                print str(p).encode('hex')
                print "error!!!!not handshake message!!"
                #print self.postprocess(data).encode('hex')
        return p

    def recv_one(self, ssock, csock):
        readable = select.select([ssock, csock], [], [], 30)[0]
        datalist = []
        for r in readable:
            record_header = recvall(r, 5)
            if len(record_header) < 5:
                continue
            length = struct.unpack(">H", record_header[3:5])[0]
            data = recvall(r, length)
            assert(len(data) == length)
            datalist.append((r, record_header + data))
        return datalist

def recvall(sock, length):
    rlen = length
    data = ''
    while rlen > 0:
        tmp = sock.recv(rlen)
        if not tmp:
            break
        data += tmp
        rlen -= len(tmp)
    return data
