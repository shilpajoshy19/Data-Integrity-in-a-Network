#!/usr/bin/python3

import MySQLdb
import hashlib
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
def dsadd(dsfilename,decd):

    sql_object = MySQLdb.connect(host="localhost",user="root",passwd="Hack123@",db="BDP")

    cursor_object = sql_object.cursor()

    dsread = open(dsfilename,"rb")
    con1 = dsread.read()
    dsread.close()

    con2 = hashcalc(decd)
    data = con2[0]
    hvalue = con2[1]
    
    mysqlquery1 = "INSERT INTO all_data (dsig,hash,data) VALUES(%s,%s,%s)"

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

def dSignature(dsigFilename):
    dsopen = open(dsigFilename, "rb")
    ds = dsopen.read()
    dsopen.close()
    return ds

def main():

    dataFile = input("Data filename?\n")
    dsigFilename = input("Digital Signature filename?\n")
    pvtKey = input(" Private Key Filename?\n")

    digital_signature = dSignature(dsigFilename)

    datacon = fileRead(dataFile)

    ddata = decryptData(datacon,pvtKey)

    dsadd(dsigFilename,decd="ddata.txt")


if __name__=="__main__":
    main()
