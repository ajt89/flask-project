import CryptoWrapper
data = "Drexel"

#testing AES
aescipher,aeskey = CryptoWrapper.aesEncrypt(data)
aesdecrypted = CryptoWrapper.aesDecrypt(aeskey, aescipher)

if data == aesdecrypted:
    print 'AES successful'
else:
    print 'AES unsuccessful'

#testing RSA
rsaPriv, rsaPub = CryptoWrapper.generateRSAKeys(1024)
rsacipher = CryptoWrapper.rsaPublicEncrypt(rsaPub, data)
rsadecrypted = CryptoWrapper.rsaPrivateDecrypt(rsaPriv, rsacipher)

print 'rsa cipher'
print rsacipher

print 'rsa decrypted'
print rsadecrypted

if data == rsadecrypted:
    print 'RSA successful'
else:
    print 'RSA unsuccessful'

#testing ECC
'''
ecc = eccGenerate()
ecccipher = eccEncrypt(ecc, data)
eccdecrypted = eccDecrypt(ecc, ecccipher)

if data == eccdecrypted:
    print 'ECC successful'
else:
    print 'ECC unsuccessful'
'''

#testing OTP
otpKey = CryptoWrapper.otpGenerate()
otpcipher = CryptoWrapper.otpEncrypt(otpKey, data)
otpdecrypt = CryptoWrapper.otpDecrypt(otpKey, otpcipher)

if data == otpdecrypt:
    print 'OTP successful'
else:
    print 'OTP unsuccessful'

print 'otp cipher'
print otpcipher

print 'otp decrypted'
print otpdecrypt

rsacipher = CryptoWrapper.rsaPublicEncrypt(rsaPub, otpKey)
print rsacipher
rsadecrypted = CryptoWrapper.rsaPrivateDecrypt(rsaPriv, rsacipher)
print rsadecrypted
print otpKey
