#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html
from header import * 
import Crypto
from Crypto.Hash import HMAC, MD5, SHA
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, ARC4, PKCS1_v1_5
import hashlib
from Crypto.Cipher import PKCS1_v1_5#,PKCS1_OAEP

import array
from collections import namedtuple
from hashlib import md5,sha1,sha256
import hmac
from prf import prfForVersion



class TLSSessionCtx(object):
    def __init__(self):
        self.packets = namedtuple('packets',['history','client','server'])
        self.packets.history=[]         #packet history
        self.packets.client = namedtuple('client',['sequence'])
        self.packets.client.sequence=0
        self.packets.server = namedtuple('server',['sequence'])
        self.packets.server.sequence=0
        
        self.params = namedtuple('params', ['handshake','negotiated',])
        self.params.handshake = namedtuple('handshake',['client','server'])
        self.params.handshake.client=None
        self.params.handshake.server=None
        self.params.negotiated = namedtuple('negotiated', ['version','ciphersuite','key_exchange','encryption','mac','compression',])
        self.params.negotiated.version=None
        self.params.negotiated.ciphersuite=None
        self.params.negotiated.isexport=None
        self.params.negotiated.key_exchange=None
        self.params.negotiated.encryption=None
        self.params.negotiated.mac=None
        self.params.negotiated.compression=None
        self.crypto = namedtuple('crypto', ['client','server'])
        self.crypto.client = namedtuple('client', ['enc','dec'])
        self.crypto.client.enc = None
        self.crypto.client.dec = None
        self.crypto.server = namedtuple('server', ['enc','dec','rsa'])
        self.crypto.server.enc = None
        self.crypto.server.dec = None
        self.crypto.server.rsa = namedtuple('rsa', ['cipher','pubkey','privkey'])
        self.crypto.server.rsa.cipher=None
        self.crypto.server.rsa.pubkey=None
        self.crypto.server.rsa.privkey=None
        self.crypto.session = namedtuple('session', ['premaster_secret','master_secret'])
        
        self.crypto.session.encrypted_premaster_secret=None
        self.crypto.session.premaster_secret=None
        self.crypto.session.master_secret=None
        self.crypto.session.randombytes = namedtuple('randombytes',['client','server'])
        self.crypto.session.randombytes.client=None
        self.crypto.session.randombytes.server=None
        
        self.crypto.session.key = namedtuple('key',['client','server'])
        self.crypto.session.key.server = namedtuple('server',['mac','encryption','iv'])
        self.crypto.session.key.server.mac = None
        self.crypto.session.key.server.encryption = None
        self.crypto.session.key.server.iv = None

        self.crypto.session.key.client = namedtuple('client',['mac','encryption','iv'])
        self.crypto.session.key.client.mac = None
        self.crypto.session.key.client.encryption = None
        self.crypto.session.key.client.iv = None
        
        self.crypto.session.key.length = namedtuple('length',['mac','encryption','iv'])
        self.crypto.session.key.length.mac = None
        self.crypto.session.key.length.encryption = None
        self.crypto.session.key.length.iv = None

        self.crypto.session.sequence = namedtuple('sequence',['client','server'])
        self.crypto.session.sequence.client=0
        self.crypto.session.sequence.server=0

        self.cumulatedmsg = ''
   
    def process(self,p):
        if p.haslayer(TLSHandshake):
            if p.haslayer(TLSClientHello):
                if not self.params.handshake.client:
                    self.params.handshake.client=p[TLSClientHello]
                    if not self.crypto.session.randombytes.client:
                        self.crypto.session.randombytes.client=struct.pack("!I",p[TLSClientHello].gmt_unix_time)+p[TLSClientHello].random_bytes
            if p.haslayer(TLSServerHello):
                if not self.params.handshake.server: 
                    self.params.handshake.server=p[TLSServerHello]
                    if not self.crypto.session.randombytes.server:
                        self.crypto.session.randombytes.server=struct.pack("!I",p[TLSServerHello].gmt_unix_time)+p[TLSServerHello].random_bytes
                if not self.params.negotiated.ciphersuite:
                    self.params.negotiated.version=p[TLSServerHello].version
                    self.params.negotiated.ciphersuite=p[TLSServerHello].cipher_suite
                    self.params.negotiated.compression=p[TLSServerHello].compression_method
                    self.parseCipherSuite()
                    #kex,enc,mac = describe_ciphersuite(self.params.negotiated.ciphersuite)
                    #self.params.negotiated.key_exchange=kex
                    #self.params.negotiated.encryption=enc
                    #self.params.negotiated.mac=mac
            if p.haslayer(TLSCertificateList):
                if self.params.negotiated.key_exchange and "RSA" in self.params.negotiated.key_exchange:
                    cert = p[TLSCertificateList].certificates[0].data
                    self.crypto.server.rsa.pubkey = PKCS1_v1_5.new(x509_extract_pubkey_from_der(cert))
            if p.haslayer(TLSClientKeyExchange) and self.crypto.server.rsa.privkey:  
                self.crypto.session.encrypted_premaster_secret = str(p[TLSClientKeyExchange].load)
                self.crypto.session.premaster_secret = self.crypto.server.rsa.cipher.decrypt(self.crypto.session.encrypted_premaster_secret,None)
                #print 'PMS',self.crypto.session.premaster_secret.encode('hex') 
                self.keysFromPreMasterSecret()
                # one for encryption and one for decryption to not mess up internal states
                self.crypto.client.enc = self.ciphersuite_factory(self.crypto.session.key.client.encryption,self.crypto.session.key.client.iv)
                self.crypto.client.dec = self.ciphersuite_factory(self.crypto.session.key.client.encryption,self.crypto.session.key.client.iv)
                self.crypto.server.enc = self.ciphersuite_factory(self.crypto.session.key.server.encryption,self.crypto.session.key.server.iv)
                self.crypto.server.dec = self.ciphersuite_factory(self.crypto.session.key.server.encryption,self.crypto.session.key.server.iv)
         

    def parseCipherSuite(self):
        cs = self.params.negotiated.ciphersuite
        macLen = HASH_LENGTH[crypto_params[TLS_CIPHER_SUITE_REGISTRY[cs]]['hash']['name']]
        keyLen = crypto_params[TLS_CIPHER_SUITE_REGISTRY[cs]]['cipher']['keyLen']
        blocksize = crypto_params[TLS_CIPHER_SUITE_REGISTRY[cs]]['cipher']['type'].block_size
        ivLen = 0 if blocksize == 1 else blocksize

        self.crypto.session.key.length.mac = macLen
        self.crypto.session.key.length.encryption = keyLen
        self.crypto.session.key.length.iv = ivLen

    def ciphersuite_factory(self, key, iv):
        cs = self.params.negotiated.ciphersuite
        if cs == 0x0035:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif cs == 0x0003 or cs == 0x0004:
            cipher = ARC4.new(key)
        else:
            raise ValueError('not supported CipherSuite')
        return cipher 

    def check_strip_mac(self, data):
        return data[:-self.crypto.session.key.length.mac]

    def clientcalhash(self, msg):
        return hmac.new(self.crypto.session.key.client.mac, msg, self.params.negotiated.mac).digest()
    def servercalhash(self, msg):
        return hmac.new(self.crypto.session.key.server.mac, msg, self.params.negotiated.mac).digest()

    def clientcalmac(self, data):
        seq_header = struct.pack('>Q', self.crypto.session.sequence.client)
        self.crypto.session.sequence.client += 1
        msg = seq_header + data;
        hashvalue = self.clientcalhash(msg)
        return hashvalue
    def servercalmac(self, data):
        seq_header = struct.pack('>Q', self.crypto.session.sequence.server)
        self.crypto.session.sequence.server += 1
        msg = seq_header + data;
        hashvalue = self.servercalhash(msg)
        return hashvalue

    def calFinish(self, finishedLabel):
        msg = md5(self.cumulatedmsg).digest() + sha1(self.cumulatedmsg).digest()
        lfinished = [0]*12
        prfForVersion(self.params.negotiated.version, lfinished, self.crypto.session.master_secret, finishedLabel, msg)
        finished = ''.join(lfinished)

        prefix = "1400000c".decode('hex')
        return prefix + finished

          
    def keysFromPreMasterSecret(self):
        version         = self.params.negotiated.version
        clientRandom    = self.crypto.session.randombytes.client
        serverRandom    = self.crypto.session.randombytes.server
        preMasterSecret = self.crypto.session.premaster_secret
        macLen  = self.crypto.session.key.length.mac
        keyLen  = self.crypto.session.key.length.encryption
        ivLen   = self.crypto.session.key.length.iv
        export  = self.params.negotiated.isexport
        masterSecretLabel = "master secret"
        keyExpansionLabel = "key expansion"
        #print 'version', version.encode('hex')
        #print 'clientrandom', clientRandom.encode('hex')
        #print 'serverrandom', serverRandom.encode('hex')
        #print macLen, keyLen, ivLen

        seed = clientRandom+serverRandom
        mastersecret = [0]*48
        prfForVersion(version,mastersecret,preMasterSecret,masterSecretLabel,seed)
        masterSecret = ''.join(mastersecret)

        seed = serverRandom+clientRandom
        n = 2*macLen + 2*keyLen + 2*ivLen
        keyBlock = [0]*n
        prfForVersion(version,keyBlock,masterSecret,keyExpansionLabel,seed)

        i=0
        clientMAC = keyBlock[i:i+macLen]
        clientMAC = ''.join(clientMAC)
        i+= macLen
        serverMAC = keyBlock[i:i+macLen]
        serverMAC = ''.join(serverMAC)
        i+=macLen

        clientKey = keyBlock[i:i+keyLen]
        clientKey = ''.join(clientKey)
        i+=keyLen
        serverKey = keyBlock[i:i+keyLen]
        serverKey = ''.join(serverKey)
        i+=keyLen

        clientIV = [0]*ivLen
        serverIV = [0]*ivLen

        if not export: #non-export
            clientIV = keyBlock[i:i+ivLen]
            clientIV = ''.join(clientIV)
            i+=ivLen
            serverIV = keyBlock[i:i+ivLen]
            serverIV = ''.join(serverIV)
        else:
            fclientKey = [0]*16
            prfForVersion(version, fclientKey, clientKey, "client write key", clientRandom+serverRandom)
            fserverKey = [0]*16
            prfForVersion(version, fserverKey, serverKey, "server write key", clientRandom+serverRandom)
            clientKey = ''.join(fclientKey)
            serverKey = ''.join(fserverKey)

            ivBlock = [0]*2*ivLen
            prfForVersion(version, ivBlock, "", "IV block", clientRandom+serverRandom)
            clientIV = ''.join(ivBlock[:ivLen])
            serverIV = ''.join(ivBlock[ivLen: 2*ivLen])

        self.crypto.session.master_secret           =   masterSecret 

        self.crypto.session.key.server.mac          =   serverMAC
        self.crypto.session.key.server.encryption   =   serverKey
        self.crypto.session.key.server.iv           =   serverIV

        self.crypto.session.key.client.mac          =   clientMAC
        self.crypto.session.key.client.encryption   =   clientKey
        self.crypto.session.key.client.iv           =   clientIV
        #print 'mastersecret', masterSecret.encode('hex')
        #print serverMAC.encode('hex'), serverKey.encode('hex'), serverIV.encode('hex')
        #print clientMAC.encode('hex'), clientKey.encode('hex'), clientIV.encode('hex')
         
          
            
    def rsa_load_key(self, pem):
        key=RSA.importKey(pem)
        return PKCS1_v1_5.new(key)

    def rsa_load_from_file(self, pemfile):
        return self.rsa_load_key(open(pemfile,'r').read())
    
    def rsa_load_privkey(self, pem):
        self.crypto.server.rsa.privkey=self.rsa_load_key(pem)
        return
    
    def tlsciphertext_decrypt(self, p, cryptfunc):
        ret = TLSRecord()
        ret.content_type, ret.version, ret.length = p[TLSRecord].content_type, p[TLSRecord].version, p[TLSRecord].length
        enc_data = p[TLSRecord].payload.load 
        
        #if self.packets.client.sequence==0:
        #    iv = self.crypto.session.key.client.iv
        decrypted = cryptfunc.decrypt(enc_data)
        
        plaintext = decrypted[:-self.crypto.session.key.length.mac-1]
        mac=decrypted[len(plaintext):]
        
        return ret/TLSCiphertextDecrypted(plaintext)/TLSCiphertextMAC(mac)


    def __repr__(self):
        params = {'id':id(self),
                  'params-handshake-client':repr(self.params.handshake.client),
                  'params-handshake-server':repr(self.params.handshake.server),
                  'params-negotiated-ciphersuite':self.params.negotiated.ciphersuite,
                  'params-negotiated-key_exchange':self.params.negotiated.key_exchange,
                  'params-negotiated-encryption':self.params.negotiated.encryption,
                  'params-negotiated-mac':self.params.negotiated.mac,
                  'params-negotiated-compression':self.params.negotiated.compression,
                  
                  'crypto-client-enc':repr(self.crypto.client.enc),
                  'crypto-client-dec':repr(self.crypto.client.dec),
                  'crypto-server-enc':repr(self.crypto.server.enc),
                  'crypto-server-dec':repr(self.crypto.server.dec),
                  
                  'crypto-server-rsa-pubkey':repr(self.crypto.server.rsa.pubkey),
                  'crypto-server-rsa-privkey':repr(self.crypto.server.rsa.privkey),
                  
                  'crypto-session-encrypted_premaster_secret':repr(self.crypto.session.encrypted_premaster_secret),
                  'crypto-session-premaster_secret':repr(self.crypto.session.premaster_secret),
                  'crypto-session-master_secret':repr(self.crypto.session.master_secret),
                  
                  'crypto-session-randombytes-client':repr(self.crypto.session.randombytes.client),
                  'crypto-session-randombytes-server':repr(self.crypto.session.randombytes.server),
                  
                  'crypto-session-key-server-mac':repr(self.crypto.session.key.server.mac),
                  'crypto-session-key-server-encryption':repr(self.crypto.session.key.server.encryption),
                  'crypto-session-key-server-iv':repr(self.crypto.session.key.server.iv),
                  
                  'crypto-session-key-client-mac':repr(self.crypto.session.key.client.mac),
                  'crypto-session-key-client-encryption':repr(self.crypto.session.key.client.encryption),
                  'crypto-session-key-client-iv':repr(self.crypto.session.key.client.iv),
                  
                  'crypto-session-key-length-mac':self.crypto.session.key.length.mac,
                  'crypto-session-key-length-encryption':self.crypto.session.key.length.encryption,
                  'crypto-session-key-length-iv':self.crypto.session.key.length.iv,
                  }

        
        str = "<TLSSessionCtx: id=%(id)s"
        
        str +="\n\t params.handshake.client=%(params-handshake-client)s"
        str +="\n\t params.handshake.server=%(params-handshake-server)s"
        str +="\n\t params.negotiated.ciphersuite=%(params-negotiated-ciphersuite)s"
        str +="\n\t params.negotiated.key_exchange=%(params-negotiated-key_exchange)s"
        str +="\n\t params.negotiated.encryption=%(params-negotiated-encryption)s"
        str +="\n\t params.negotiated.mac=%(params-negotiated-mac)s"
        str +="\n\t params.negotiated.compression=%(params-negotiated-compression)s"
        
        str +="\n\t crypto.client.enc=%(crypto-client-enc)s"
        str +="\n\t crypto.client.dec=%(crypto-client-dec)s"
        str +="\n\t crypto.server.enc=%(crypto-server-enc)s"
        str +="\n\t crypto.server.dec=%(crypto-server-dec)s"
        
        str +="\n\t crypto.server.rsa.privkey=%(crypto-server-rsa-privkey)s"
        str +="\n\t crypto.server.rsa.pubkey=%(crypto-server-rsa-pubkey)s"
        
        str +="\n\t crypto.session.encrypted_premaster_secret=%(crypto-session-encrypted_premaster_secret)s"
        str +="\n\t crypto.session.premaster_secret=%(crypto-session-premaster_secret)s"
        str +="\n\t crypto.session.master_secret=%(crypto-session-master_secret)s"
        
        str +="\n\t crypto.session.randombytes.client=%(crypto-session-randombytes-client)s"
        str +="\n\t crypto.session.randombytes.server=%(crypto-session-randombytes-server)s"

        str +="\n\t crypto.session.key.client.mac=%(crypto-session-key-client-mac)s"
        str +="\n\t crypto.session.key.client.encryption=%(crypto-session-key-client-encryption)s"
        str +="\n\t crypto.session.key.cllient.iv=%(crypto-session-key-client-iv)s"

        str +="\n\t crypto.session.key.server.mac=%(crypto-session-key-server-mac)s"
        str +="\n\t crypto.session.key.server.encryption=%(crypto-session-key-server-encryption)s"
        str +="\n\t crypto.session.key.server.iv=%(crypto-session-key-server-iv)s"
        
        str +="\n\t crypto.session.key.length.mac=%(crypto-session-key-length-mac)s"
        str +="\n\t crypto.session.key.length.encryption=%(crypto-session-key-length-encryption)s"
        str +="\n\t crypto.session.key.length.iv=%(crypto-session-key-length-iv)s"
        
        str += "\n>"
        return str%params
    
