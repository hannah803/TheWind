from scapy.all import *
useOrinAddr = True

def clienthelloprocess(csession, ssession, p):
    p[TLSHandshake].version = '\x03\x00'
    p[TLSHandshake].cipher_suites_length = 2
    p[TLSHandshake].cipher_suites = 0
    p[TLSHandshake].length = len(str(p[TLSClientHello]))
    p.length = len(str(p[TLSHandshake]))
    return p

def serverhelloprocess(csession, ssession, p):
    return p

def certificateprocess(csession, ssession, p):
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
