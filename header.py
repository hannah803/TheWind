#!/usr/bin/env python
#encoding: utf-8

import socket, select, struct
PORT = 8888
SO_ORIGINAL_DST = 80

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

def recv_one(ssock, csock):
    readable = select.select([ssock, csock], [], [], 30)[0]
    datalist = []
    if len(readable) == 0:
        print "none is readable!!!"
    for r in readable:
        record_header = recvall(r, 5)
        if len(record_header) < 5:
            continue
        length = struct.unpack(">H", record_header[3:5])[0]
        data = recvall(r, length)
        assert(len(data) == length)
        datalist.append((r, record_header + data))
    return datalist

def recvall(client, length):
    rlen = length
    data = ''
    while rlen > 0:
        tmp = client.recv(rlen)
        if not tmp:
            break
        data += tmp
        rlen -= len(tmp)
    return data

def read_line(client):
    line = ''
    while True:
        s = client.recv(1)
        if not s:
            break
        if s == '\n':
            break
        line += s
    return line

def get_original_addr(csock):
    odestdata = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
    address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
    return address, port
