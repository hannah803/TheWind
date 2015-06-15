import socket, select, struct
from scapy.layers.ssl_tls import TLSRecord
from handlessl import *

class HandleOPENVPN:
    client_ctl_begin = False
    client_ctl_end = False
    server_ctl_begin = False
    server_ctl_end = False
    client_content = ""
    server_content = ""
    handlessl = HandleSSL()

    def handle(self, p, label):
        if p.opcode == 4:
            if label == "client":
                #print "===client begin==="
                #print "client", p.msg_fragment.encode('hex')
                #print self.server_ctl_begin, self.server_ctl_end
                if self.server_ctl_begin and not self.server_ctl_end:
                    pro_len = 0
                    while 1:
                        length = struct.unpack('>H',self.server_content[pro_len+3:pro_len+5])[0]
                        print length
                        payload = self.server_content[pro_len:pro_len+5+length]
                        self.handlessl.handle(TLSRecord(payload), 'server')
                        print payload.encode('hex')
                        pro_len = pro_len+5+length
                        if pro_len == len(self.server_content):
                            break
                    self.server_ctl_bebin = False
                    self.server_ctl_end = True
                self.client_content += p.msg_fragment
                self.client_ctl_begin = True
                self.client_ctl_end = False
                #print "===client_end==="
            elif label == "server":
                #print "===server begin==="
                #print "server", p.msg_fragment.encode('hex')
                #print self.client_ctl_begin, self.client_ctl_end
                if self.client_ctl_begin and not self.client_ctl_end:
                    pro_len = 0
                    while 1:
                        length = struct.unpack('>H',self.client_content[pro_len+3:pro_len+5])[0]
                        print length
                        payload = self.client_content[pro_len:pro_len+5+length]
                        self.handlessl.handle(TLSRecord(payload), 'client')
                        print payload.encode('hex')
                        pro_len = pro_len+5+length
                        if pro_len == len(self.client_content):
                            break
                    self.client_ctl_begin = False
                    self.client_ctl_end = True
                self.server_content += p.msg_fragment    
                self.server_ctl_begin = True
                self.server_ctl_end = False
                #print "===server end==="


        return p

    def recv_one(self, ssock, csock):
        readable = select.select([ssock, csock], [], [], 30)[0]
        datalist = []
        if len(readable) == 0:
            print "none is readable!!!"
        for r in readable:
            first_read = recvall(r, 2)
            if len(first_read) < 2:
                continue
            length = struct.unpack(">H", first_read)[0]
            data = recvall(r, length)
            assert(len(data) == length)
            datalist.append((r, first_read + data))
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
