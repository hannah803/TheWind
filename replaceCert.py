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
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, file('cert.pem').read()) 
    print cert
    p.payload.payload.certificates[0] = file('cert.der').read()
    #del p.payload.payload.certificates[0]
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
    pubkey = str(p[Raw])[:64]
    csession.crypto.server.rsa.pubkey = pubkey
    ssession.crypto.server.rsa.pubkey = pubkey
    prikey = getD(pubkey)

    n = int(pubkey.encode('hex'), 16)
    e = long(65537)
    d = int(getD(pubkey).encode('hex'), 16)
    csession.crypto.server.rsa.privkey = prikey
    ssession.crypto.server.rsa.privkey = prikey
    key = RSA.construct((n, e, d))
    csession.crypto.server.rsa.cipher = PKCS1_v1_5.new(key)
    ssession.crypto.server.rsa.cipher = PKCS1_v1_5.new(key)
    return p

def clientfinishprocess(csession, ssession, p):
    if not verify_client_finished(csession, p):
        print "Client Finshed Verify Error!!"
    return forge_client_finished(ssession, p)

def serverfinishprocess(csession, ssession, p):
    if not verify_server_finished(ssession, p):
        print "Server Finshed Verify Error!!"
    return forge_server_finished(csession, p)

def clientchangecsprocess(csession, ssession, p):
    return p

def serverchangecsprocess(csession, ssession, p):
    return p

def clientappdataprocess(csession, ssession, p):
    dec = csession.crypto.client.dec.decrypt(str(p)[5:])
    dec = csession.check_strip_mac(dec)
    print 'CLIENT=>SERVER\n', dec
    pdata = str(p)[:3]+struct.pack('>H',len(dec))+dec
    mac = ssession.clientcalmac(pdata)
    enc = ssession.crypto.client.enc.encrypt(dec+mac)
    return str(p)[:3]+struct.pack('>H',len(enc))+enc

def serverappdataprocess(csession, ssession, p):
    dec = ssession.crypto.server.dec.decrypt(str(p)[5:])
    dec = ssession.check_strip_mac(dec)
    print 'SERVER=>CLIENT:\n', dec
    pdata = str(p)[:3]+struct.pack('>H',len(dec))+dec
    mac = csession.servercalmac(pdata)
    enc = csession.crypto.server.enc.encrypt(dec+mac)
    return str(p)[:3]+struct.pack('>H',len(enc))+enc



def verify_client_finished(csession, p):
    decfinish = csession.crypto.client.dec.decrypt(str(p)[5:])
    decmac = decfinish[16:]
    decfinish = decfinish[:16]
    mac = csession.clientcalmac(str(p)[:3]+struct.pack('>H', len(decfinish))+decfinish)
    if mac != decmac:
        raise ValueError('Finish Mac Error')
    caledfinish = csession.calFinish('client finished')
    csession.cumulatedmsg += caledfinish
    return decfinish == caledfinish

def verify_server_finished(ssession, p):
    decfinish = ssession.crypto.server.dec.decrypt(str(p)[5:])
    decmac = decfinish[16:]
    decfinish = decfinish[:16]
    mac = ssession.servercalmac(str(p)[:3]+struct.pack('>H', len(decfinish))+decfinish)
    if mac != decmac:
        raise ValueError('Finish Mac Error')
    caledfinish = ssession.calFinish('server finished')
    ssession.cumulatedmsg += caledfinish
    return decfinish == caledfinish



def forge_client_finished(ssession, p):
    forged_finish = ssession.calFinish('client finished')
    ssession.cumulatedmsg += forged_finish
    forged_mac = ssession.clientcalmac(str(p)[:3]+struct.pack('>H',len(forged_finish))+forged_finish)
    enc = ssession.crypto.client.enc.encrypt(forged_finish + forged_mac)
    return str(p)[:3]+struct.pack('>H',len(enc))+enc

def forge_server_finished(csession, p):
    forged_finish = csession.calFinish('server finished')
    csession.cumulatedmsg += forged_finish
    forged_mac = csession.servercalmac(str(p)[:3]+struct.pack('>H',len(forged_finish))+forged_finish)
    enc = csession.crypto.server.enc.encrypt(forged_finish + forged_mac)
    return str(p)[:3]+struct.pack('>H',len(enc))+enc
