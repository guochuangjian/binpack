import os
import struct
import json

VALUE     = "value"
FMT       = "fmt"
STRUCTURE = "structure"
DEFINES   = "defines"
# types = ("uint8", "int8", "uint16", "int16", "uint", "int", "uint64", "int64", \
        #  "float", "double", "string", "struct")
types = {
    "uint8":'B',
    "int8":'b',
    "uint16":'H',
    "int16":'h',
    "uint":"I",
    "int":'i',
    "uint64":'Q',
    "int64":'q',
    "float":'f',
    "double":'d',
    "string":'c'
}

sizes = {
    "uint8":1,
    "int8":1,
    "uint16":2,
    "int16":2,
    "uint":4,
    "int":4,
    "uint64":8,
    "int64":8,
    "float":4,
    "double":4,
    "string":1
}

numbers = ("uint8", "int8", "uint16", "int16", "uint", "int", "uint64", "int64")

types_size = {}

def _type2fmt(type, num):
    for key, value in types.items():
        if type == key:
            return value * num
    return None

def _dict2fmt(s_dict):
    fmt = ''
    for key, value in s_dict.items():
        if type(value) is type({}):
            print("value type error!")
            continue
        num = 1
        if '[' in value:
            print(key, value)
            #截取数组大小
            num = int(value[value.find('[') + 1: value.find(']')])
            value = value[:value.find('[')]
        fmt = fmt + _type2fmt(value, num)
    return fmt

def _dict2value(d_dict):
    values = ()
    for key, value in d_dict.items():
        if type(value) is type({}):
            print("value type error!")
            continue

    return values

def struct_pack(json_path):
    fd = open(json_path, "r")
    struct_json =json.load(fd)
    fd.close()
    #print(struct_json)
    if STRUCTURE not in struct_json.keys() or DEFINES not in struct_json.keys():
        print("[%s] or [%s] not exist!" % STRUCTURE, DEFINES)
        return
    ss = struct_json[STRUCTURE]
    dd = struct_json[DEFINES]
    s_dict = {}
    for s_key in ss.keys():
        s_dict[s_key] = {}
        s_dict[s_key][FMT] = _dict2fmt(ss[s_key])

    for d_key in dd.keys():
        if d_key not in s_dict.keys():
            print("not this structure[%s]" % d_key) 
            continue
        #todo check key
        value = _dict2value(dd[d_key])
        s = struct.Struct(s_dict[d_key][FMT])
        s_dict[d_key][VALUE] = s.pack(*value)

    return s_dict

class structpack(object):
    def __init__(self, json_str):
        self.__s_info = json.loads(json_str)
        self.__convert()

    def __type2fmt(self, type):
        for key, value in types.items():
            if type == key:
                return value
        return None

    def __type2size(self, type):
        for key, value in sizes.items():
            if type == key:
                return value
        return None

    def __struct_info_gen(self, s_key, info):
        struct_info = {} 
        for member, value in info.items():
            struct_info[member] = {}
            struct_info[member]["name"] = member 
            num = 1
            if '[' in value:
                #截取数组大小
                num = int(value[value.find('[') + 1: value.find(']')])
                value = value[:value.find('[')]
            if value not in types.keys():
                print("member type not define!")
                return
            struct_info[member]["type"] = value
            struct_info[member]["num"]  = num
            struct_info[member]["size"] = self.__type2size(value)
            struct_info[member]["fmt"]  = (str(num) if num > 1 else '') + self.__type2fmt(value)
        self.__s_dict[s_key] = struct_info

    def __val_convert(self, value_info, value):
        value_type = value_info["type"]
        num        = value_info["num"]
        if value_type == "string":
            if num > len(value):
                value = value + '\0' * (num - len(value))
            else:
                value = value[:num]
            return value
        elif value_type == "float" or value_type == "double":
            if num == 1:
                return float(value)
            else:
                data = []
                values = value.split(",")
                for i in range(num):
                    data.append(float(values[i]) if i < len(values) else 0.0)
                return tuple(data)
        elif value_type in numbers:
            if num == 1:
                return int(value, 16 if ('0x' or '0X') in value else 10)
            else:
                values = value.split(",")
                data = []
                for i in range(num):
                    data.append(int(values[i], 16 if ('0x' or '0X') in values else 10) \
                                if i < len(values) else 0)
                return tuple(data)
        else:
            print("value type unsupport!")
            return None

    def __value_gen(self, d_key, dd):
        for key, value in dd.items():
            value_info = self.__s_dict[d_key][key] 
            data = self.__val_convert(value_info, value)
            self.__s_dict[d_key][key].update({"value":data})

    def __convert(self):
        self.__s_dict = {}
        if STRUCTURE not in self.__s_info.keys() or DEFINES not in self.__s_info.keys():
            print("[%s] or [%s] not exist!" % STRUCTURE, DEFINES)
            return
        ss = self.__s_info[STRUCTURE] #struct info
        dd = self.__s_info[DEFINES]   #struct defines
        for s_key in ss.keys():  #s_key: struct define
            self.__struct_info_gen(s_key, ss[s_key])
        #defines find
        for d_key in dd.keys():
            if d_key not in self.__s_dict.keys():
                print("not this structure[%s]" % d_key) 
                continue
            self.__value_gen(d_key, dd[d_key])

    def fmt(self, struct_name):
        fmt = ''
        for member, info in self.__s_dict[struct_name].items():
           fmt = fmt + info["fmt"]
        return fmt

    def value(self, struct_name, prefix_fmt = ''):
        if struct_name not in self.__s_dict.keys():
            return None
        values = []
        for member, info in self.__s_dict[struct_name].items():
            value = info["value"]
            if type(value) == str:
                for i in range(len(value)):
                    values.append(bytes(value[i], encoding="utf-8"))
            elif type(value) == tuple or type == list:
                for data in value:
                    values.append(data)
            elif type(value) == int or type(type) == float:
                values.append(value)
            else:
                print("data type error!")
        s = struct.Struct(prefix_fmt + self.fmt(struct_name))
        return s.pack(*tuple(values))         

if __name__ == "__main__":
    path = "./samples/demo.json"
#    print(struct_pack(path))

    with open(path, "r") as fd:
        json_str = fd.read()
    binhead = structpack(json_str)
    print(binhead.fmt("bin_head"))
    with open("bindata.bin", "wb") as fd:
        data = binhead.value("bin_head")
        fd.write(data)
        print(data)
