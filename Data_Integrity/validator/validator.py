#!/usr/bin/python3

import MySQLdb
import hashlib
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def fileRead(dataFile):
    file_ = open(dataFile, "rb")
    filecon = file_.read()
    file_.close()
    return filecon

def hashcalc(decd):
    fileread = open(decd,"rb")
    filecon = fileread.read()
    fileread.close()

    hash_ = hashlib.sha256(filecon)
    hvalue = hash_.hexdigest()

    return filecon,hvalue

#adding data to mysql table
def dsadd(dsfilename,decd,flag):

    sql_object = MySQLdb.connect(host="localhost",user="root",passwd="Hack123@",db="rbase")

    cursor_object = sql_object.cursor()

    dsread = open(dsfilename,"rb")
    con1 = dsread.read()
    dsread.close()

    con2 = hashcalc(decd)
    data = con2[0]
    hvalue = con2[1]
    
    if flag == 1:
        mysqlquery1 = "INSERT INTO valid_data (dsig,hash,data) VALUES(%s,%s,%s)"
    else:
        mysqlquery1 = "INSERT INTO invalid_data (dsig,hash,data) VALUES(%s,%s,%s)"

    cursor_object.execute(mysqlquery1, (con1,hvalue,data,))

    sql_object.commit()
    sql_object.close()

def decryptData(datacon,pvtKey):
    pkopen = open(pvtKey, "rb")
    pk = pkopen.read()
    pkopen.close()
    
    pkey = RSA.importKey(pk)
    cipherkey = PKCS1_OAEP.new(pkey)
    ddata = cipherkey.decrypt(datacon)

    ddatawrite = open("ddata.txt", "wb")
    ddatawrite.write(ddata)
    ddatawrite.close()

    return ddata

def hashGen(datacon):
    hashin = SHA256.new(datacon)
    hash_ = hashin.hexdigest()
    return hashin

def dSignature(dsigFilename):
    dsopen = open(dsigFilename, "rb")
    ds = dsopen.read()
    dsopen.close()
    return ds

def dsVerify(hash_,pubKey,digital_signature,dsigFilename,decd):
    
    keyfile = open(pubKey, "rb")
    pubkey = keyfile.read()
    keyfile.close()

    pubkeyObject = RSA.importKey(pubkey)
    sigObject = PKCS1_v1_5.new(pubkeyObject)
    
    if sigObject.verify(hash_,digital_signature):
        print("Valid Data!")
        dsadd(dsigFilename,decd,flag=1)
    else:
        print("Invalid Data!")
        dsadd(dsigFilename,decd,flag=0)


def main():
    
    dataFile = input("Data filename?\n")
    dsigFilename = input("Digital Signature filename?\n")
    pvtKey = input(" Private Key Filename?\n")
    pubKey = input(" Public Key Filename?\n")

    digital_signature = dSignature(dsigFilename)

    datacon = fileRead(dataFile)

    ddata = decryptData(datacon,pvtKey)
    
    hash_ = hashGen(ddata)

    dsVerify(hash_,pubKey,digital_signature,dsigFilename,decd="ddata.txt")

if __name__=="__main__":
    main()
