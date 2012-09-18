#!/usr/bin/python

import hashlib
import socket
import struct
import base64
import hmac
import time

DIRhello = "Hello %s calling\n"
#DIRhello = "Hello *UserAgent* calling\n"
DIROKhello = "1000 OK:"

PASSWORD = "EgodaEnaYUnocmD+4uggDNOLXhOJiWGc2qwlA3B/su6g"

class Bsocket(object):
    '''use to send and receive the response from director'''

    def __init__(self,src_host=None, src_port=None):
        self.msg = None
        self.msg_len = 0
        
        self.src_host = src_host
        self.src_port = src_port
        self.my_name = 'bconsole' 
        # after connect get the sockaddr
        self.socket = None

    def connect(self,):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.src_host, self.src_port))

    def send(self, msg=None):
        '''use socket to send request to director '''
        if self.socket==None:
            raise RuntimeError("should connect to director first before send data")
        self.msg = msg
        self.msg_len = len(self.msg) # plus the msglen info
        
        self.socket.send(struct.pack("!i", self.msg_len) + self.msg) # convert to network flow
        print "send message:%s" %(self.msg)
        self.msg = ""
        self.msg_len = 0

    def recv(self,):
        '''will receive data from director '''
        if self.socket == None:
            raise RuntimeError("should connect to director first before recv data")
        nbyte = 0
        # first get the message length
        msg = self.socket.recv(4)
        if len(msg) <= 0:
            # perhaps some signal command
            #raise RuntimeError("get the msglen error")
            return False
        # get the message
        nbyte = struct.unpack("!i", msg)[0]
        self.msg = self.socket.recv(nbyte)
        self.msg_len = nbyte
        print "get the message:%s" %(self.msg)
        return True



def cram_md5_respond(dir, password, tls_remote_need=0, compatiable=True):
    '''client connect to dir, the dir confiirm the password and the config is correct '''
    # receive from the director
    chal = ""
    ssl = 0
    result = False
    if not dir.recv():
        return (0, True, False)
    # check the receive message
    msg_list = dir.msg.split(" ")
    chal = msg_list[2]
    # get th timestamp and the tle info from director response
    ssl = int(msg_list[3][4] )
    compatiable = True
    # hmac chal and the password
    hmac_md5 = hmac.new(password)
    hmac_md5.update(chal)
    
    # base64 encoding
    msg = base64.b64encode(hmac_md5.digest()).rstrip('=')
    # cut off the '==' after the base64 encode
    # because the bacula base64 encode is not compatiable for the rest world 
    # so here we should do some to fix it

    # send the base64 encoding to director
    dir.send(msg)
    time.sleep(1)
    dir.recv()
    if dir.msg == "1000 OK auth\n":
        result = True
    return (ssl, compatiable, result)

def cram_md5_challenge(dir, password, tls_local_need=0, compatiable=True):
    '''client launch the confirm, client confirm the dir is the correct director '''
    
    # get the timestamp
    # here i did not do what bacula real do
    # here is the consoel to confirm the director so can do this on bconsole`way 
    local_time = time.time()
    chal = 'auth cram-md5 <%.5f@%s> ssl=%s' %(local_time, dir.my_name, tls_local_need)
    # send the confirmation
    dir.send(chal)
    # get the response
    
    # hash with password 
    hmac_md5 = hmac.new(password)
    hmac_md5.update(chal)
    hmac_comp = base64.b64encode(hmac_md5.digest()).rstrip('=')
    time.sleep(1) 
    dir.recv()
    is_correct = hmac_comp == dir.msg
    if is_correct:
        dir.send("1000 OK auth\n")
    else:
        dir.send("1999 Authorization failed.\n")
    # encode to base64

    # check the response is equal to base64
    return is_correct

def authenticate_director(dir, password, clientname="*UserAgent*"):
    '''authenticate the director
        if the authenticate success return True else False
        dir: the director location
        clientname: the client calling always be *UserAgent*'''
    compatiable = True
    bashed_name = ""
    bashed_name = DIRhello %(clientname)
    # send the bash to the director
    dir.send(bashed_name)
    result = cram_md5_respond(dir=dir, password=password, tls_remote_need=0, compatiable=compatiable)
    if (not result[2] 
        or (not cram_md5_challenge(dir=dir, password=password, tls_local_need=0, compatiable=compatiable))):
        # not success complete the authenticate
        return False
    return True

def process_password(password):
    '''
    md5 the password and return the hex style
    '''
    md5 = hashlib.md5()
    md5.update(password)
    return md5.hexdigest()

if __name__ == '__main__':
    dir = Bsocket("192.168.6.231", 9101)
    dir.connect()
    if authenticate_director(dir, password=process_password(PASSWORD),):
        print "authenticate success"
    else:
        print "authenticate failed"
