from header import *

def clienthelloprocess(csession, ssession, p):
    print "Version:%s"%(TLS_VERSIONS[p[TLSHandshake].version])
    print "ClientRandom:%s"%p[TLSHandshake].random_bytes.encode('hex')
    return p

def serverhelloprocess(csession, ssession, p):
    print "ServerRandom:%s"%p[TLSHandshake].random_bytes.encode('hex')
    print "CipherSuite:%s"%parseCS(p[TLSHandshake].cipher_suite)
    print "CompressionMethod:%s"%p[TLSHandshake].compression_method
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
