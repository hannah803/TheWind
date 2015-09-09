from scapy.all import *
from OpenSSL import crypto
b_process = True
SSL = True
OPENVPN = False
def clienthelloprocess(csession, ssession, p):
    return p

def serverhelloprocess(csession, ssession, p):
    return p

def certificateprocess(csession, ssession, p):
    #cert = crypto.load_certificate(crypto.FILETYPE_PEM, file('cert.pem').read()) 
    #print cert
    p.payload.payload.certificates[0] = file('cert.der').read()
    del p.payload.payload.certificates[1]
    new_len = 0
    for i in range(len(p.payload.payload.certificates)):
       new_len += p.payload.payload.certificates[i].length + 3
    p.payload.payload.length = new_len
    p.payload.length = new_len + 3
    p.length = new_len + 7
    return p

def clientkeyexgprocess(csession, ssession, p):
    return p

def serverkeyexgprocess(csession, ssession, p):
    return p

def clientfinishprocess(csession, ssession, p):
    return p

def serverfinishprocess(csession, ssession, p):
    return p

def clientchangecsprocess(csession, ssession, p):
    return p

def serverchangecsprocess(csession, ssession, p):
    return p

def clientappdataprocess(csession, ssession, p):
    return p

def serverappdataprocess(csession, ssession, p):
    return p
