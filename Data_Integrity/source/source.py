#!/usr/bin/python3

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def fileRead(dataFile):
    file_ = open(dataFile, "rb")
    filecon = file_.read()
    file_.close()
    return filecon

def dataEncrypt(datacon,publicKey):
    keyfile = open(publicKey, "rb")
    pkey = keyfile.read()
    keyfile.close()

    pkeyObject = RSA.importKey(pkey)
    cipherkey = PKCS1_OAEP.new(pkeyObject)
    edata = cipherkey.encrypt(datacon)
    
    encryptfile = open("edata.txt", "wb")
    encryptfile.write(edata)
    encryptfile.close()

def hashGen(datacon):
    hashin = SHA256.new(datacon)
    hash_ = hashin.hexdigest()
    return hashin

def dSign(hash_,privateKey):
    
    keyfile = open(privateKey, "rb")
    pkey = keyfile.read()
    keyfile.close()

    pkeyObject = RSA.importKey(pkey)
    sigObject = PKCS1_v1_5.new(pkeyObject)
    dsig = sigObject.sign(hash_)

    sigFile = open("digital_signature", "wb")
    sigFile.write(dsig)
    sigFile.close()


def main():
    
    dataFile = input("Data filename?\n")
    publicKey = input("Public key filename?\n")
    privateKey = input("Private key filename?\n")

    datacon = fileRead(dataFile)
    
    hash_ = hashGen(datacon)

    edata = dataEncrypt(datacon,publicKey)

    dSign(hash_,privateKey)

if __name__=="__main__":
    main()
