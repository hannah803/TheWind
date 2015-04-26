from hashlib import md5, sha1, sha256
import hmac
#PRF basic functions
def pHash(result,secret,seed,hashfunc):
        a=hmac.new(secret,seed,hashfunc).digest()
        j=0
        while j<len(result):
                b = hmac.new(secret,a+seed,hashfunc).digest()
                todo = len(b)
                if j+todo > len(result):
                        todo=len(result)-j
                result[j:j+todo] = b[0:todo]
                j+=todo
                a=hmac.new(secret,a,hashfunc).digest()

#TLS 1.0 and TLS 1.1 pseudo-random function
def prf10(result,secret,label,seed):
        labelandseed = label+seed
        s1,s2 = secret[0:(len(secret)+1)/2],secret[len(secret)/2:]
        pHash(result,s1,labelandseed,md5)

        result2 = [0]*len(result)
        pHash(result2,s2,labelandseed,sha1)
        for i in range(len(result2)):
                s = ord(result[i]) ^ ord(result2[i])
                result[i] = chr(s)
    
#TLS 1.2 pseudo-random function
def prf12(result,secret,label,seed):
        labelandseed = label+seed
        pHash(result,secret,labelandseed,sha256)

#SSL 3.0 prf
def prf30(result,secret,label,seed):
    done=0
    i =0
    while done < len(result):
        pad = '' 
        for j in range(0,i+1):
            pad += chr(ord('A')+i)
        digest = sha1(pad[:i+1]+secret+seed).digest()

        t = md5(secret+digest).digest()
        todo = len(t)
        if len(result)-done < todo:
            todo = len(result)-done
        result[done:done+todo] = t[:todo]
        done += todo
        i+=1

def prfForVersion(version,result,secret,label,seed):
    if version ==  '\x03\x00':
            return prf30(result,secret,label,seed)
    elif version == '\x03\x01' or version == '\x03\x02' or version == '\x01\00':
            return prf10(result,secret,label,seed)
    elif version ==  '\x03\x03':
            return prf12(result,secret,label,seed)
    else:
        raise Exception("Unknow version type!")

