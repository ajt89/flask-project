import os
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
from ast import literal_eval
import onetimepad
import string
import random

'''AES Cipher Specifics'''
blockSize = 16          #Block Size
keySize = 32            #keySize in Bytes - 32 bytes = 256bit Encryption
mode = AES.MODE_CBC     #Cipher Block Mode

def __init__():
    
    pass

def generateAES():
    key = id_generator()
    return key

def aesEncrypt(aes, data):
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
    unpad = lambda s : s[0:-ord(s[-1])]
    data = pad(data)
    iv = Random.new().read(AES.block_size);
    cipher = AES.new(aes, AES.MODE_CBC, iv )
    return ( iv + cipher.encrypt( data ) ).encode("hex")

def aesDecrypt( aes, data ):
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
    unpad = lambda s : s[0:-ord(s[-1])]
    data = data.decode("hex")
    iv = data[:16]
    data= data[16:]
    cipher = AES.new(aes, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( data))

def generateRSAKeys(keyLength):
    '''Generates Public/Private Key Pair - Returns Public / Private Keys'''
    private = RSA.generate(keyLength)
    public  = private.publickey()
    privateKey = private.exportKey()
    publicKey = public.exportKey()
    return privateKey, publicKey

def rsaPublicEncrypt(pubKey, data):
    '''RSA Encryption Function - Returns Encrypted Data'''
    publicKey = RSA.importKey(pubKey)
    encryptedData = publicKey.encrypt(data,'')
    return encryptedData
     
def rsaPrivateDecrypt(privKey, data):
    '''RSA Decryption Function - Returns Decrypted Data'''
    #import pdb; pdb.set_trace();
    privateKey = RSA.importKey(privKey)
    decryptedData = privateKey.decrypt(data)
    return decryptedData

def id_generator(size=keySize, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def otpGenerate():
    key = id_generator()
    return key

def otpEncrypt(otp, data):
    '''Encrypts Data with OTP key'''
    encrypted = onetimepad.encrypt(data, otp)
    return encrypted

def otpDecrypt(otp, data):
    '''Decrypts Data with OTP key'''
    decrypted = onetimepad.decrypt(data, otp)
    return decrypted