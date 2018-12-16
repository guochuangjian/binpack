#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import struct

#intel-hex 格式说明
#:LLAAAARRDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDZZ
#LL——长度,单位，byte
#AAAA——16 bit 地址
#RR——类型
# - 00 数据记录 (data record)
# - 01 结束记录 (end record)
# - 02 扩展段地址记录 (paragraph record)
# - 03 转移地址记录 (transfer address record)
# - 04 扩展线性地址记录 (expand address record)
# - 05 开始线性地址记录
#DD——16byte数据
#ZZ——校验

def hex2bin(hex_file, bin_file):
    del_bin = 0
    with open(hex_file, 'rb') as hex_fd, \
        open(bin_file, 'wb') as bin_fd:
        for hex_str in hex_fd.readlines():
            hex_str = hex_str.strip()  #remove '\n\r\t'
            size    = int(hex_str[1:3], 16)
            dtype   = int(hex_str[7:9], 16)
            if dtype == 0: #Data
                for i in range(size):
                    bin_fd.write(struct.pack('B', int(hex_str[(9 + i * 2):(9 + i * 2 + 2)], 16)))
            elif dtype == 1: #End
                print("End")
                break
            elif dtype == 2: 
                print("[HEX86]:Expand addr: 0x%0X" % (int(hex_str[9 : 13], 16) << 4))
            elif dtype == 3: 
                print("[HEX86]Start addr : 0x%X" % (int(hex_str[9:17], 16)))
            elif dtype == 4: #Start
                print("[HEX386]:Expand addr: 0x%X" % ((int(hex_str[9 : 13], 16) << 16)))
            elif dtype == 5: 
                print("[HEX386]Start addr : 0x%X" % (int(hex_str[9:17], 16)))
            else:
                print("hex format error, data type %d!" % dtype)
                del_bin = 1
                break
    if del_bin :
        os.unlink(bin_file)

#[HEX386]
def bin2hex(bin_file, addr, hex_file):
    with open(bin_file, 'rb') as bin_fd, \
        open(hex_file, 'wb') as hex_fd:
        #write addr
        if addr < (64 * 1024):
            buf  = [0x00, (addr >> 8) & 0xFF, addr & 0xFF, 0x05]
        else:
            base_addr = addr >> 16 
            buf  = [0x02, 0x00, 0x00, 0x04, base_addr >> 8, base_addr & 0xFF]
        buf.append(0x100 - sum(buf))
        hex_fd.writelines(':' + ''.join(['%02x'.upper() % tmp for tmp in buf]) + '\r\n')

        #write data
        offset = addr % (64 * 1024)
        wr_addr = 0
        while True:
            line = bin_fd.read(16)
            if len(line) <= 0:
                break

            #ready line
            dbuf = [ord(val) for val in line]
            buf  = [len(line) & 0xFF, (wr_addr >> 8) & 0xFF, wr_addr & 0xFF, 0x00]
            buf += dbuf
            buf.append((0x100 - (sum(buf) & 0xFF)) & 0xFF)

            #write data line
            hex_fd.writelines(':' + ''.join('%02X'.upper() % val for val in buf) + '\r\n')
        
            offset += len(line)
            if (addr + offset) % (64 * 1024) == 0:
                print("new addr : %08x" % (addr + offset))
                #write new line
                wr_addr = 0
                addr = (addr + offset) >> 16 
                buf  = [0x02, 0x00, 0x00, 0x04, (addr >> 8) & 0xFF, addr & 0xFF]
                buf.append((0x100 - (sum(buf) & 0xFF)) & 0xFF)
                hex_fd.writelines(':' + ''.join(['%02x'.upper() % tmp for tmp in buf]) + '\r\n')
            else:
                wr_addr += len(line)  

        #write end
        hex_fd.writelines(":00000001FF\r\n")
             
def bin_combine(bin1_file, bin2_file, bin2_addr, output_bin, padding_byte = 0xFF):
    bin1_len = os.path.getsize(bin1_file)
    with open(bin1_file, "rb") as bin1_fd, \
        open(bin2_file, "rb") as bin2_fd, \
        open(output_bin, "wb") as output_fd:
        output_fd.write(bin1_fd.read())
        if bin2_addr < bin1_len:
            print("Error:bin1 file len >= bin2 addr!")
            os.unlink(output_bin)
        output_fd.write(struct.pack('B', padding_byte) * (bin2_addr - bin1_len))
        output_fd.write(bin2_fd.read())

if __name__ == "__main__":
    # print("test hex to bin file!")
    # hex_file = input("hex file path:")
    # bin_file = input("generate bin file path:")
    # hex2bin(hex_file, bin_file)
    # print("test hex2bin ok!")

    # print("test bin to hex file!")
    # bin_file = "./bb.bin"
    # hex_file = "./output_hh.hex"
    # offset  = 0x8000000
    # bin_file = input("bin file path:")
    # hex_file = input("generate hex file path:")
    # offset   = input("hex file offset:")
    # bin2hex(bin_file, offset, hex_file)
    print("test bin2hex ok!")

    # print("test bin combine!")
    # bin1_file = input("bin1 file path:")
    # bin2_file = input("bin2 file path:")
    # bin_file  = input("combine file path:")
    # addr      = input("bin2 file addr:")
    # bin1_file = "boot.bin"
    # bin2_file = "app.bin"
    # addr = 16* 1024
    # bin_file = "fw.bin"
    # bin_combine(bin1_file, bin2_file, addr, bin_file)
     