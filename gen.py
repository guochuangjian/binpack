#!/usr/bin/python
import os
import sys
import json
import struct

def app_info_handle(app_name, app_info):
    with open(app_name, 'r') as app_fd:
        pass
    tmp_app_name = app_name + ".tmp"
    with open(tmp_app_name, "w") as tmp_fd:
        pass

    for info in app_info :
        print(info)


def boot_info_handle(boot_name, boot_info):
    pass

if __name__ == "__main__":
    if (len(sys.argv) > 1):
        json_file = sys.argv[1]
    else:
        json_file = input("Enter Firmware JSON Root:")

    with open(json_file, "r") as fd:
        json_str = fd.read()
    json_obj = json.loads(json_str)

    if ("app_root" not in json_obj.keys()) or \
       ("output" not in json_obj.keys()):
       print("No [app_root] or [output] key")
       exit()

    if "app_info" in json_obj.keys():
        app_info_handle(json_obj["app_root"], json_obj["app_info"])

    if "boot_info" in json_obj.keys():
        boot_info_handle(json_obj["boot_root"], json_obj["boot_info"]) 

    if "output_firmware" in json_obj["output"].keys():
        pass

    if "update_app" in json_obj["output"].keys():
        pass


    print(json_obj)
    os.system("pause")