import socket
import sys
import os
import shutil
import time
import subprocess
import binascii
from multiprocessing import Process
from multiprocessing import Process, Queue

from Groundtruth import *


ToolName = "BinPRE"


#-------need change before test different protocols-------
pcap_name = sys.argv[1] + "_50"
protocol_name = sys.argv[1]
evaluation_mode = sys.argv[5]#index
endian = sys.argv[6]
restartFlag = int(sys.argv[7])
threshold = 0.8

isUDP = False
settimeout = 2
sendtimedelay = 0.2
text_flag = 0
wait_time = 5
Reconnect = False




Syntax_Groundtruth = eval(protocol_name + "_Syntax_Groundtruth")
Semantic_Groundtruth = eval(protocol_name + "_Semantic_Groundtruth")
Semantic_Functions_Groundtruth = eval(protocol_name + "_Semantic_Functions_Groundtruth")
commandOffset = eval(protocol_name + "_commandOffset")
lengthOffset = eval(protocol_name + "_lengthOffset")


ip = "127.0.0.1"
port = 0
#-------------no need to change----------------------------------------------


input_pcap_dir = f"./pcaps/{pcap_name}.pcap" 
ToolRes_path = f"../BinPRE_Res/{pcap_name}/{pcap_name}_after_explore.txt"
Evaluation_Res = f"../BinPRE_Res/{pcap_name}/{pcap_name}_eval.txt"
Evaluation_bo_Res = f"../BinPRE_Res/{pcap_name}/{pcap_name}_bo_eval.txt"
Boofuzz_oa_Res = f"../BinPRE_Res/{pcap_name}/{pcap_name}_boofuzz_oa.txt"
Boofuzz_bo_Res = f"../BinPRE_Res/{pcap_name}/{pcap_name}_boofuzz_bo.txt"


baseline_mode = ""
threadId = 1
serverArgs = "e"
defaultCommand = '0,1'


PUT_test = f'../PUT_test'
info_file_path = f'../PUT_test/tmp_results/info.txt'
format_file_path = f'../PUT_test/tmp_results/format.txt'
data_file_path = f'../PUT_test/tmp_results/data.txt'
debug_file_path = f'../PUT_test/tmp_results/debug.txt'
loops_file_path = f'../PUT_test/tmp_results/loops.txt'
verbose_file_path = f'../PUT_test/tmp_results/verbose.txt'


black_operators = ['mov','movzx','cmp']

semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']

semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']

#----------------




def connect(ip, port, isUDP):
    if isUDP:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.settimeout(settimeout)
    try:
        if protocol_name == "tftp":
            sock.bind(('', 7788))
        else:
            sock.connect((ip, port))#normal
        
        print("The connection is successful!")
        return sock
    except:
        print("The connection failed!")
        return False

def wait_connect(ip, port, isUDP):
    while 1:
        sock = connect(ip, port, isUDP)
        if sock: break
        time.sleep(0.5)
    return sock


def reset_directory(directory_path):
    if os.path.exists(directory_path):
        shutil.rmtree(directory_path)
        os.mkdir(directory_path)
    else:
        os.mkdir(directory_path)

def reset_file(file_path):
    with open(file_path, "w") as file:
        file.write("")

def get_file_size(file_path):
    return os.path.getsize(file_path)


def write_to_file_AAA(new_directory,data):
    with open(new_directory + 'AAA_ourApproach.txt', 'a') as o:
        o.write(data + '\n')
    o.close()


def MsgToPayload(msg_Content):
    bytes_string = []
    msgline = msg_Content.strip('\t\n')
    msgline = msgline.split(' ')
    for c in msgline:
        c = c.strip('()')
        bytes_string.append(int(c,16))
    msgPayload = bytes(bytes_string)
    return msgPayload

def write_to_file(result_dir,data):
    with open(result_dir + 'format.txt', 'a', encoding='utf-8') as f:
        f.write(data + '\n')
    f.close()

def compare_key_1(key):
    return (key.count(","), key)


def compare_key_2(item):
    return int(item[0].split(",")[0])


def compare_key_3(item):
    return int(item.split(';')[0].split(",")[0])

def notConformCommand(message_Result,template_field,template_format):
    if template_field.count(',') > 3:
        return True
    elif (template_field in message_Result[0].field_funcs) and (semantic_Functions[2] in message_Result[0].field_funcs[template_field]):
        return True
    elif (template_field in message_Result[0].field_types) and (semantic_Types[3] in message_Result[0].field_types[template_field]):
        return True
    elif template_field == template_format[-1]:
        return True
    else:
        return False

def notConformLength(direction_pos, message_Result, index, f_value, f_end, checksum_size):

    if direction_pos not in message_Result[index].boundaries and \
        (f_value != (message_Result[index].boundaries[-1] - message_Result[index].boundaries[0])) and \
        (((message_Result[index].boundaries[-1] - f_value) < f_end) or ((message_Result[index].boundaries[-1] - f_value) not in message_Result[index].boundaries)) and \
        ((f_end + f_value + checksum_size) not in message_Result[index].boundaries):
        return True
    else:
        return False
