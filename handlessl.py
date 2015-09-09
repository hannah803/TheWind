from ssl_tls_crypto import *
from config import *

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
    def __init__(self):
        self.clientfinished = False
        self.serverfinished = False
        self.csession = TLSSessionCtx()
        self.ssession = TLSSessionCtx()
        self.process = False

    def handle(self, p, label):
        content_type = p.content_type
        if content_type == HANDSHAKE:
            p = self.processHandshake(p, label, self.process)
        elif content_type == CHANGE_CIPHER_SPEC:
            assert(p.length == 1)
            assert(p.message == '\x01')
            if label == "client":
                logging.info("CLIENT_CHANGE_CIPHER_SPEC")
                self.clientfinished = True
            if label == "server":
                logging.info("SERVER_CHANGE_CIPHER_SPEC")
                self.serverfinished = True
        elif content_type == ALERT:
            logging.info("ALERT")
        elif content_type == APPLICATION_DATA:
            #logging.info('-'*80)
            #logging.info('-'*29 + 'APPLICATION_DATA BEGIN' + '-'*29)
            #logging.info('-'*80)
            if label == "client":
                logging.info("CLIENT APPLICATION DATA")
                p = clientappdataprocess(self.csession, self.ssession, p)
            if label == "server":
                logging.info("SERVER APPLICATION DATA")
                p = serverappdataprocess(self.csession, self.ssession, p)
            #logging.info('-'*80)
            #logging.info('-'*29 + 'APPLICATION_DATA END' + '-'*29)
            #logging.info('-'*80)
        return p

    def processHandshake(self, p, label, process):
        hs_type = ord(str(p)[5])  #hacks here
        if hs_type == HELLO_REQUEST:
            logging.info("HELLO_REQUEST")
        elif hs_type == CLIENT_HELLO and not (self.clientfinished or self.serverfinished):
            logging.info("CLIENT_HELLO")
            if process == True:
                self.csession.cumulatedmsg += str(p)[5:]
                self.csession.process(p)
            p = clienthelloprocess(self.csession, self.ssession, p)
            if process == True:
                self.ssession.cumulatedmsg += str(p)[5:]
                self.ssession.process(p)
        elif hs_type == SERVER_HELLO and not (self.clientfinished or self.serverfinished):
            logging.info("SERVER_HELLO")
            if process == True:
                self.ssession.cumulatedmsg += str(p)[5:]
                self.ssession.process(p)
            p = serverhelloprocess(self.csession, self.ssession, p)
            if process == True:
                self.csession.cumulatedmsg += str(p)[5:]
                self.csession.process(p)
        elif hs_type == CERTIFICATE and not (self.clientfinished or self.serverfinished):
            logging.info("CERTIFICATE")
            if process == True:
                self.csession.cumulatedmsg += str(p)[5:]
                self.csession.process(p)
            p = certificateprocess(self.csession, self.ssession, p)
            if process == True:
                self.ssession.cumulatedmsg += str(p)[5:]
                self.ssession.process(p)
        elif hs_type == SERVER_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
            logging.info("SERVER_KEY_EXCHANGE")
            if process == True:
                self.ssession.cumulatedmsg += str(p)[5:]
                self.ssession.process(p)
            p = serverkeyexgprocess(self.csession, self.ssession, p)
            if process == True:
                self.csession.cumulatedmsg += str(p)[5:]
                self.csession.process(p)
        elif hs_type == CERTIFICATE_REQUEST:
            logging.info("CERTIFICATE_REQUEST")
        elif hs_type == SERVER_HELLO_DONE and not (self.clientfinished or self.serverfinished):
            logging.info("SERVER_HELLO_DONE")
            if process == True:
                self.csession.cumulatedmsg += str(p)[5:]
                self.csession.process(p)
                self.ssession.process(p)
                self.ssession.cumulatedmsg += str(p)[5:]
        elif hs_type == CERTIFICATE_VERIFY:
            logging.info("CERTIFICATE_VERIFY")
        elif hs_type == CLIENT_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
            logging.info("CLIENT_KEY_EXCHANGE")
            if process == True:
                self.csession.cumulatedmsg += str(p)[5:]
                self.csession.process(p)
            p = clientkeyexgprocess(self.csession, self.ssession, p)
            if process == True:
                self.ssession.cumulatedmsg += str(p)[5:]
                self.ssession.process(p)
        elif hs_type == CERTIFICATE_STATUS:
            logging.info("CERTIFICATE_STATUS")
        else:
            if label == 'client' and self.clientfinished:
                logging.info("CLIENT_ENCRYPTED_HS_MSG")
                #logging.info(str(p).encode('hex'))
                #logging.info(p.show())
                p = clientfinishprocess(self.csession, self.ssession, p)
            elif label == 'server' and self.serverfinished:
                logging.info("SERVER_ENCRYPTED_HS_MSG")
                #logging.info(str(p).encode('hex'))
                #logging.info(p.show())
                p = serverfinishprocess(self.csession, self.ssession, p)
            else:
                logging.info('label:%s, clientFinished:%s, serverFinished:%s'%(label, self.clientfinished, self.serverfinished))
                logging.info(str(p).encode('hex'))
                logging.warning("not handshake message!!")
                #logging.info(self.postprocess(data).encode('hex'))
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

