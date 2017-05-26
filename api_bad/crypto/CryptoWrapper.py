import os
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
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

def __generateAESKeystring__():
    '''Generates Pseudo Random AES Key and Base64 Encodes Key - Returns AES Key'''
    key = os.urandom(keySize)
    keyString = base64.urlsafe_b64encode(str(key))
    return keyString
    
def __extractAESKey__(keyString):
    '''Extracts Key from Base64 Encoding'''
    key = base64.urlsafe_b64decode(keyString)
    if len(key) != keySize:
        raise Exception('Error: Key Invalid')
        os._exit(1)
    return key

def __extractCrypto__(encryptedContent):
    '''Decodes Base64 Encoded Crypto'''
    cipherText = base64.urlsafe_b64decode(encryptedContent)
    return cipherText

def __encodeCrypto__(encryptedContent):
    '''Encodes Crypto with Base64'''
    encodedCrypto = base64.urlsafe_b64encode(str(encryptedContent))
    return encodedCrypto

def generateAESKeys():
    key = __generateAESKeystring__()
    return key

def aesEncrypt(key, data):
    '''Encrypts Data w/ pseudo randomly generated key and base64 encodes cipher - Returns Encrypted Content and AES Key'''
    encryptionKey = __extractAESKey__(key)
    pad = blockSize - len(data) % blockSize
    data = data + pad * chr(pad)
    iv = os.urandom(blockSize)
    cipherText = AES.new(encryptionKey, mode, iv).encrypt(data)
    encryptedContent = iv + cipherText
    encryptedContent = __encodeCrypto__(encryptedContent)
    return encryptedContent

def aesDecrypt(key, data):
    '''Decrypts AES(base64 encoded) Crypto - Returns Decrypted Data'''
    decryptionKey = __extractAESKey__(key)
    encryptedContent = __extractCrypto__(data)
    iv = encryptedContent[:blockSize] 
    cipherText = encryptedContent[blockSize:]
    plainTextwithpad = AES.new(decryptionKey, mode, iv).decrypt(cipherText)
    pad = ord(plainTextwithpad[-1])
    plainText = plainTextwithpad[:-pad]
    return plainText

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