import os
import struct
import hashlib
import binascii
from Crypto.Cipher import AES

'''
# \brief : bin file replace data
# file_path[string]: file path
# addr[int]: file offset
# data[bytes]:replace data 
'''
def replace_data(file_path, addr, data):
    with open(file_path, "rb+") as fd:
        fd.seek(addr, 0)
        fd.write(bytes(data))

def insert_data(file_path, addr, data, output_path):
    with open(file_path, "rb") as fd :
        file_data = fd.read()
    with open(output_path, "wb") as output_fd:
        if addr > len(file_data):
            print("arg:addr error!")
            return
        output_fd.write(file_data[0:addr])
        output_fd.write(bytes(data))
        output_fd.write(file_data[addr:])

def md5_get(file_path):
    with open(file_path, "rb") as fd:
        md5 = hashlib.md5(fd.read()).hexdigest()
    return bytes(md5, encoding="utf-8")       

def aes_cbc_encrypt(file_path, key, iv, output_path):
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    with open(file_path, "rb") as fd, open(output_path, "wb") as output_fd:
        while True:
            data = fd.read(16)
            length = len(data)
            #read end exit
            if length <= 0:
                break
            elif length != 16:
                data = data + (b'\0' * (16 - length))
            enc_data = cryptor.encrypt(data)
            output_fd.write(enc_data)

def aes_ecb_encrypt(file_path, key, output_path):
    cryptor = AES.new(key, AES.MODE_ECB)
    with open(file_path, "rb") as fd, open(output_path, "wb") as output_fd:
        while True:
            data = fd.read(16)
            length = len(data)
            #read end exit
            if length <= 0:
                break
            elif length != 16:
                data = data + (b'\0' * (16 - length))
            enc_data = cryptor.encrypt(data)
            output_fd.write(enc_data)

if __name__ == "__main__":
    path = "./test.bin"
    # aes_ecb_encrypt(path, b"1234567890123456", enc_path)