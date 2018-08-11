#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import json
import struct
import hashlib
import binascii

class firmware_tool(object):
    def __init__(self, json_file):
        self.load_json(json_file)

    #def __init__(self):
        #self.json_obj = None

    def load_json(self, json_file):
        with open(json_file, "r", encoding="utf-8") as fd:
             json_str = fd.read()
        self.json_obj = json.loads(json_str)
        
    def str_is_hex(self, str):
        return ("0x" in str) or ("0X" in str)

    def str_is_bin(self, str):
        return ("0b" in str) or ("0B" in str)

    def str2num(self, str):
        if self.str_is_hex(str):
            return int(str, 16)
        elif self.str_is_bin(str):
            return int(str, 2)
        else:
            return int(str, 10)

    def file_path_info_get(self, file):
        (path, name) = os.path.split(file)
        (file_name, ext) = os.path.splitext(name)
        return (path, file_name, ext)

    def data2hexline(self, addr, data):
        #dbuf = [ord(str(val)) for val in data]
        dbuf = data
        buf  = [len(data) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF, 0x00]
        buf += dbuf
        buf.append((0x100 - (sum(buf) & 0xFF)) & 0xFF)
        return ':' + ''.join('%02x'.upper() % val for val in buf) + '\r\n'

#intel-hex 格式
#:LLAAAARRDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDZZ
#LL——长度,单位，byte
#AAAA——16 bit 地址
#RR——类型
# - 00 数据记录 (data record)
# - 01 结束记录 (end record)
# - 02 扩展段地址记录 (paragraph record)
# - 03 转移地址记录 (transfer address record)
# - 04 扩展线性地址记录 (expand address record)
#DD——16byte数据
#ZZ——校验
    def bin2hex(self, bin_name, start, hex_name):
        with open(bin_name, 'rb') as f_bin, \
            open(hex_name, 'wb') as f_hex:
            if start < 64 * 1024:
                buf  = [0x00, (start >> 8) & 0xFF, start & 0xFF, 0x05]
            else:
                addr = start >> 16 
                buf  = [0x02, 0x00, 0x00, 0x04, addr >> 8, addr & 0xFF]
            buf.append(0x100 - sum(buf))
            tmp=":".encode() +  \
                      "".join(['%02x'.upper() % tmp for tmp in buf]).encode() + \
                      "\r\n".encode()
            f_hex.write(tmp)
            offset  = start % (64 * 1024)
            wr_addr = 0
            while True:
                line = f_bin.read(16)
                if (len(line) <= 0):
                    break
                
                #write data
                f_hex.write(self.data2hexline(wr_addr, line).encode("utf-8"))
                
                offset += len(line)
                if (start + offset) % (64 * 1024) == 0:
                    print("new addr : %08x" % (start + offset))
                    #write new line
                    wr_addr = 0
                    addr = (start + offset) >> 16 
                    buf  = [0x02, 0x00, 0x00, 0x04, (addr >> 8) & 0xff, addr & 0xff]
                    buf.append((0x100 - (sum(buf) & 0xff)) & 0xff)
                    f_hex.write((':' + ''.join(['%02x'.upper() % tmp for tmp in buf]) \
                                        + '\r\n').encode("utf-8"))
                else:
                    wr_addr += len(line)
            #write end
            f_hex.write((":00000001ff\r\n").encode("utf-8"))
        
    def hex2bin(self, hex_path, bin_path):
        hex_fd = open(hex_path, 'rb')
        bin_fd = open(bin_path, 'wb')

        for hex_str in hex_fd.readlines():
            hex_str = hex_str.strip()
            size    = int(hex_str[1:3], 16)
            dtype   = int(hex_str[7:9], 16)
            if dtype == 0: #Data
                #data = int(hex_str[10 + i, 10 + i + 2], 16) for i in range(size)
                for i in range(size):
                    data += int(hex_str(10 + i, 10 + i + 2), 16)
                bin_fd.write(data)
            elif dtype == 1: #End
                pass
            elif dtype == 4: #Start
                pass
            else:
                print("hex format error!")
                break

        hex_fd.close()
        bin_fd.close()

    def bin_combine(self, bin1_name, bin1_start, bin1_size, \
                    bin2_name, output_bin_name):
        bin1_act_len = os.path.getsize(bin1_name)  
        if bin1_act_len > bin1_size:
            print("bin size too bigger!\r\n")
            return False
        bin1_rlen = bin1_size - bin1_act_len
        with open(bin1_name, 'rb') as f_bin1, \
            open(bin2_name, 'rb') as f_bin2, \
            open(output_bin_name, 'wb') as f_bin:
            f_bin.write(f_bin1.read())
            if bin1_rlen:
                f_bin.write(('\xFF' * bin1_rlen).encode('utf-8'))
            f_bin.write(f_bin2.read())
        return True

    def file_md5_get(self, filename):
        fd = open(filename, 'rb')
        md5 = hashlib.md5(fd.read()).hexdigest()
        fd.close()
        return bytes(md5, encoding="utf-8")       

    def file_crc32_get(self, filename):
        with open(filename, 'rb') as fd:
            crc32 = binascii.crc32(fd.read())
        return bytes(crc32, encoding="utf-8")

    def number2bin(self, number, size):
        if size == 1:
            return struct.pack('B', number)
        elif size == 2:
            return struct.pack('H', number)
        elif size == 4:
            return struct.pack('I', number)
        elif size == 8:
            return struct.pack('Q', number)
        else:
            return None

    def __insert_info_handle(self, bin_path, bin_info):
        with open(bin_path, 'rb+') as app_fd:
            for key, info in bin_info.items():
                if "desc" == key:
                    continue

                addr  = self.str2num(info["addr"])
                size  = info["size"]

                app_fd.seek(addr, 1)

                #fixme allow insert self-define key handle

                value_type  = info["type"]
                if value_type == "number":
                    app_fd.write(self.number2bin(self.str2num(info["value"]), size))
                elif value_type == "string":
                    value = info["value"]
                    if len(value) >= size:
                        wr_str = value[0:size-1] + '\0'
                    else:
                        wr_str = value + (size - len(value)) * '\0'
                    app_fd.write(wr_str.encode("utf-8"))
                elif value_type == "array":
                    print("array not support")
                else:
                    print("[%s][%s] type error!" % key, value_type)
        return True
    
    def __add_info_handle(self, bin_path, add_info, output_path):
        ret = True
        bin_fd = open(bin_path, "rb")
        output_fd = open(output_path, "wb")
        bin_size = os.path.getsize(bin_path)

        #delete invalid key
        if "desc" in add_info.keys():
            add_info.pop("desc")
        new_add_info = sorted(add_info.items(), key=lambda x:self.str2num(x[1]["addr"]))
        rd_addr = 0
        for item in new_add_info:
            key  = item[0]
            info = item[1]
            addr = self.str2num(info["addr"])
            size = info["size"]
            
            if rd_addr != addr:
                bin_fd.seek(addr)
                rd_addr = addr
                output_fd.write(bin_fd.read(addr - rd_addr))
                
            if key == "bin_size":
                output_fd.write(self.number2bin(bin_size, size))        
            elif key == "encrypt":
                enc_type = info["type"]
                print("[%s]Not Support Encrypt Type!" % key)
                ret = False
                break
            elif key == "verify":
                verify_type = info["type"]
                if verify_type == "md5":
                    md5 = self.file_md5_get(bin_path)
                    output_fd.write(md5)
                elif verify_type == "crc32":
                    crc32 = self.file_crc32_get(bin_path)
                    output_fd.write(crc32)
                else:
                    print("Not Support Verify-Type!")
                    break
            else: #normal key
                value_type = info["type"]
                if value_type == "number":
                    output_fd.write(self.number2bin(self.str2num(info["value"], size)))
                elif value_type == "string":
                    value = info["value"]
                    if len(value) >= size:
                        wr_str = value[0:size-1] + '\0'
                    else:
                        wr_str = value + (size - len(value)) * '\0'
                    output_fd.write(wr_str)
                else:
                    print("[%s]Not Support Type!" % key)

        bin_fd.close()
        output_fd.close()
        return ret

    def __combine_app_and_boot(self, combine_info, output_path):
        if "app" not in combine_info.keys() or \
            "boot" not in combine_info.keys():
            print("[app] or [boot] not in [combine]")
            return False
        app_info = combine_info["app"]
        boot_info = combine_info["boot"]

        if "start_addr" not in app_info.keys() or \
            "max_size" not in app_info.keys():
            print("[start_addr] or [max_size] not in [app]")
            return False

        if "start_addr" not in boot_info.keys() or \
            "max_size" not in boot_info.keys():
            print("[start_addr] or [max_size] not in [boot]")
            return False
        
        boot_addr = self.str2num(boot_info["start_addr"])
        boot_size = self.str2num(boot_info["max_size"])

        app_addr  = self.str2num(app_info["start_addr"])
        app_size  = self.str2num(app_info["max_size"])

        self.bin_combine(self.boot_path, boot_addr, boot_size,\
                         self.app_path, output_path)
        return True

    def __app_output_handle(self, output_info):
        if "output_path" not in output_info.keys():
            print("Not [output_path] key!")
            return False
        output_path = output_info["output_path"]

        path, name, ext = self.file_path_info_get(output_path)
        if ext == ".hex":
            bin_output_path = path + "//" + name + ".bin"
        else:
            bin_output_path = output_path

        if "combine" in output_info.keys():
            if self.__combine_app_and_boot(output_info["combine"], bin_output_path) != True:
                print("Combine APP and Boot Failed!")
                return False
        
        if "add_info" in output_info.keys():
            if self.__add_info_handle(self.app_path, \
                                      output_info["add_info"], \
                                      bin_output_path) != True:
                print("Add Info Failed!")
                return False

        if ext == ".hex":
            addr = self.str2num(output_info["output_addr"])
            self.bin2hex(bin_output_path, addr, output_path)
        return True

    def __update_ouput_handle(self, update_info):
        if "output_path" not in update_info.keys():
            print("Not [output_path] key!")
            return False

        if "add_info" in update_info.keys():
            if self.__add_info_handle(self.app_path, \
                                      update_info["add_info"], 
                                      update_info["output_path"]) != True:
                print("Add Info Failed!")
                return False
        return True

    def __file2bin(self, path):
        file_path, file_name, file_fmt = self.file_path_info_get(path)
        if (file_fmt != ".bin") and (file_fmt != ".hex"):
            print("file format error!")
            return False
        if file_fmt == ".hex":
            self.hex2bin(path, file_path + file_name + ".bin")
        return True

    def __chk_app_and_boot(self):
        if self.__file2bin(self.app_path) != True:
            return False
        path, name, ext = self.file_path_info_get(self.app_path)

        if self.boot_path != None:
            if self.__file2bin(self.boot_path) != True:
                return False
        return True

    def run(self):
        if ("app_path" not in self.json_obj.keys()) or \
           ("output" not in self.json_obj.keys()):
            print("No [app_path] or [output] key!")
            return 

        if ("output_firmware" not in self.json_obj["output"].keys()) and \
           ("update_app" not in self.json_obj["output"].keys()):
            print("No output info!")
            return 
            
        self.output = self.json_obj["output"]
        
        # self.app_path  = json_obj["app_path"]
        # if "boot_path" in self.json_obj.keys():
        #     self.boot_path = json_obj["boot_path"]
        # else:
        #     self.boot_path = None

        path, file_name, ext = self.file_path_info_get(self.json_obj["app_path"])
        tmp_app_path = path + "//" + file_name + "_tmp" + ext
        with open(self.json_obj["app_path"], 'rb') as app_fd, open(tmp_app_path, 'wb') as tmp_fd:
            tmp_fd.write(app_fd.read())
        self.app_path = tmp_app_path

        if "boot_path" in self.json_obj.keys():
            path, file_name, ext = self.file_path_info_get(self.json_obj["boot_path"])
            tmp_boot_path = path + "//" + file_name + "_tmp" + ext
            with open(self.json_obj["boot_path"], 'rb') as boot_fd, open(tmp_boot_path, 'wb') as tmp_fd:
                tmp_fd.write(boot_fd.read())
        self.boot_path = tmp_boot_path 

        #check app and boot file format, must be bin
        if self.__chk_app_and_boot() != True:
            print("file format error!")
            return 
    
        if "app_info" in self.json_obj.keys():
            if self.__insert_info_handle(self.app_path, self.json_obj["app_info"]) != True:
                print("insert app info error!")
                return

        if (self.boot_path != None) and \
           ("boot_info" in self.json_obj.keys()) : 
            if self.__insert_info_handle(self.boot_path, self.json_obj["boot_info"]) != True:
                print("insert boot info error!")
                return 

        if "output_firmware" in self.output.keys():
            if self.__app_output_handle(self.output["output_firmware"]) != True:
                print("handle output firmware falied!")
                return 

        if "update_app" in self.output.keys():
            if self.__update_ouput_handle(self.output["update_app"]) != True:
                print("handle update app failed!")
                return 



if __name__ == "__main__":
    # if len(sys.argv) > 1:
    #     json_file = sys.argv[1]
    # else:
    #     json_file = input("Please Enter JSON Path:")
    json_file = "D:/Git//MCUFirmwareTool//samples//demo.json"
    fwt = firmware_tool(json_file)
    fwt.run()
    os.system("pause")