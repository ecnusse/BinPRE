#-*- coding:utf-8 -*-

import random
import socket
import time
import sys
import os
import shutil
from scapy.all import *
from scapy.all import IP, TCP, Raw, rdpcap
import Separator
import Corrector
import config
import copy
import fcntl
import binascii

from AAA_Evaluation import *


info_file_path = config.info_file_path
format_file_path = config.format_file_path

class Message:
    def __init__(self, ip_src, ip_dst, sport, dport, app_data):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.sport = sport
        self.dport = dport
        self.app_data = app_data

modbus = []
s7 = []
eip = []
dnp3 = []
tftp = []
dns = []
ftp = []
http = []

def process_packet(packet, targetport):
    if IP in packet and TCP in packet:    #TCP 
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        srcport = packet[TCP].sport
        destport = packet[TCP].dport

        if packet.haslayer(Raw) and packet.dport == targetport:
            app_data = packet[Raw].load
            message = Message(ip_src, ip_dst, srcport, destport, app_data)
            return message
        
    elif IP in packet and UDP in packet:  #UDP
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        srcport = packet[UDP].sport
        destport = packet[UDP].dport

        if IP in packet and UDP in packet and DNS in packet and destport == targetport:
            app_data = bytes(packet[DNS])
            message = Message(ip_src, ip_dst, srcport, destport, app_data)
            return message
        
        elif IP in packet and UDP in packet and TFTP in packet and destport == targetport:
            app_data = bytes(packet[TFTP])
            message = Message(ip_src, ip_dst, srcport, destport, app_data)
            return message
        


    return None
    

def print_all_messages(all_messages):
    for message in all_messages:
        print(f"IP Source: {message.ip_src}, IP Destination: {message.ip_dst}")
        print(f"Source Port: {message.sport}, Destination Port: {message.dport}")
        print("Application Layer Data:")
        print(message.app_data)
        print("\n")


# print baseline results used in boofuzz
def Print_bo_Res(payload_message, Polyglot_Syntax, Polyglot_length_Res, Polyglot_command_Res, AutoFormat_ftrees, Tupni_Syntax):
    
    with open(config.Boofuzz_bo_Res, "a") as file:
        
        for i in range(0,len(payload_message)):
            file.write(f"\n\n\n\t########## Msg {i} ########## \n")
            file.write(f"Application Layer Data:{payload_message[i]}\n")
            file.write(f"\nPolyglot Syntax----------------------\n")
            file.write(f"{Polyglot_Syntax[i]}\n")
            file.write(f"\tPolyglot Command:{Polyglot_command_Res[i]}\n")
            file.write(f"\tPolyglot Length:{Polyglot_length_Res[i]}\n")


            file.write(f"\nAutoFormat Syntax----------------------\n")
            file.write(f"{AutoFormat_ftrees[i]}\n")

            file.write(f"\nTupni Syntax----------------------\n")
            file.write(f"{Tupni_Syntax[i]}\n")


def remove_analysis(directory_path):
    try:
        os.remove(directory_path + '/AAA_ourApproach.txt')
        os.remove(directory_path + '/inst.txt')
        os.remove(directory_path + '/tree.txt')
        os.remove(directory_path + '/tree_optimize_1.png')
        os.remove(directory_path + '/tree_optimize_2.png')
        os.remove(directory_path + '/tree_origin.png')
        os.remove(directory_path + '/semantics.txt')
    except:
        print("check file! " + directory_path)
        

def SendInputMsg():
    print("start sending")
    isUDP = False
    proto = sys.argv[1]

    # argv[2]analysis mode:0, 1
    try:
        manual_flag = int(sys.argv[2])
        if(manual_flag == 1):
            print("Manual mode")
        elif(manual_flag == 0):
            print("Automatic mode")
        elif(manual_flag == 2):
            print("Only Analysis with existing tmp_results")
    except:
        manual_flag = 0
        print("Automatic mode")

    # argv[3]protocol type:0, 1
    try:
        text_flag = int(sys.argv[3])
        if(text_flag == 1):
            print("Text protocol")
        else:
            print("Binary protocol")
    except:
        text_flag = 0
        print("Binary protocol")    
    config.text_flag = text_flag

    '''Configuration information for the protocol port number. Modify or add as you need.'''
    if proto == "dnp3":
        data = dnp3
        port = 4999
        config.port = port
        port = 20000
    elif proto == "eip":
        data = eip
        port = 44818
        config.port = port
    elif proto == "modbus":
        data = modbus
        port = 502  
        config.port = port
    elif proto == "s7":
        data = s7
        port = 102
        config.port = port
    elif proto =="ftp":
        data = ftp
        port = 21
        config.port = port
    elif proto =="dns":
        port = 53
        config.port = port
        data = dns
        isUDP = True
    elif proto =="tftp":
        port = 69
        config.port = port
        data = tftp
        isUDP = True
    elif proto =="http":
        port = 80
        config.port = port
        data = http
    elif proto =="unknown":
        port = config.port
    

    config.isUDP = isUDP
    ip = config.ip

        
    all_messages = []
    payload_message = []
    #argv[4]baseline mode:oa, bo, all
    if(manual_flag == 1):
        payload_message = data
        try:
            baseline_mode = sys.argv[4]
        except:
            baseline_mode = "all"
        
    elif(manual_flag == 0):
        try:
            baseline_mode = sys.argv[4]
        except:
            baseline_mode = "all"
        pcap_file = config.input_pcap_dir
        packets = rdpcap(pcap_file)
        
        for packet in packets:  
            '''Pcap packet parsing. Modify or add as you need.'''
            message = process_packet(packet, port)
            
            if(message is not None):
                all_messages.append(message)
                payload_message.append(message.app_data)

            
        print_all_messages(all_messages)
        
    elif(manual_flag == 2):
        try:
            index = int(sys.argv[4])
        except:
            print("Please enter message number!")
            
        try:
            baseline_mode = sys.argv[4]
        except:
            baseline_mode = "all"
            
        for i in range(index):
            new_directory = f"../PUT_test/{i}_tmp_results"
            remove_analysis(new_directory)

    print(payload_message)

    config.baseline_mode = baseline_mode
    
    if manual_flag == 0 or manual_flag == 1:
        time.sleep(10)
        sock = config.wait_connect(ip, config.port, isUDP)
        index = 0
        
        while 1:
            print("index: {}".format(index))
            try:
                d = payload_message[index] #
            except IndexError:
                print("Message samples exhausted")
                break
            print("\nsend DATA: {}".format(d))
            info_before_send_size = config.get_file_size(info_file_path)
            format_before_send_size = config.get_file_size(format_file_path)
            print("info_before_send_size:{}".format(info_before_send_size))
            print("format_before_send_size:{}".format(format_before_send_size))
            


            if config.isUDP:
                sock.sendto(d, (config.ip, config.port))
            else:
                try:
                    sock.send(d)
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"!!!!----Rconnect socket!!!!----")
                    sock = config.wait_connect(ip, config.port, isUDP)
                    continue

            print("send {}".format(" ".join(hex(c) for c in d))) 


             
                
            recv_empty_flag = 0
            while 1:
                try:            
                    recv_content = sock.recv(255)
                    print("recv {}".format(" ".join(hex(c) for c in recv_content)))
                    break
                except socket.timeout: 
                    break
                if(recv_content == b""):
                    recv_empty_flag += 1
                if(recv_empty_flag >= 10):
                    print("Warning! Multiple recv empty detected.")
                    break

            time.sleep(config.wait_time)                
            
            if config.Reconnect:
                sock.close()
                sock = config.wait_connect(ip, port, isUDP)

            info_after_recv_size = config.get_file_size(info_file_path)

            
            # info.txt 
            if info_after_recv_size > info_before_send_size:
                with open(info_file_path, 'rb') as file:
                    file.seek(info_before_send_size)
                    infodata = file.read(info_after_recv_size - info_before_send_size)
                
                with open(info_file_path, 'wb') as file:
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX)  
                    file.truncate(0)
                    time.sleep(3)  
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)  
                
                
                with open(f'../PUT_test/tmp_results/info_{index}.txt', 'wb') as output_file:
                    output_file.write(infodata)
                    output_file.close()
                    print(f'../PUT_test/tmp_results/info_{index}.txt {info_before_send_size}-{info_after_recv_size}')
                info_before_send_size = info_after_recv_size    
            
            format_after_recv_size = config.get_file_size(format_file_path)
            print("format_after_recv_size:{}".format(format_after_recv_size))
            if format_after_recv_size > format_before_send_size:
                with open(format_file_path, 'rb') as file:
                    file.seek(format_before_send_size)
                    infodata = file.read(format_after_recv_size - format_before_send_size)


                with open(f'../PUT_test/tmp_results/format_{index}.txt', 'wb') as output_file:
                    output_file.write(infodata)
                    output_file.close()
                    print(f'../PUT_test/tmp_results/format_{index}.txt {format_before_send_size}-{format_after_recv_size}')
                format_before_send_size = format_after_recv_size  
            else:
                print(f"!!!!----Resend Message{index}")
                index -= 1
                time.sleep(10)
                    


            index += 1

        
        print("Please wait, processing files...")
        for i in range(index):
            new_directory = f"../PUT_test/{i}_tmp_results"
            config.reset_directory(new_directory)
            shutil.move(f'../PUT_test/tmp_results/info_{i}.txt', new_directory + '/info.txt')
            shutil.move(f'../PUT_test/tmp_results/format_{i}.txt', new_directory + '/format.txt')
            shutil.copy('../PUT_test/tmp_results/data.txt', new_directory)
            shutil.copy('../PUT_test/tmp_results/debug.txt', new_directory)
            shutil.copy('../PUT_test/tmp_results/loops.txt', new_directory)
            shutil.copy('../PUT_test/tmp_results/verbose.txt', new_directory)
        
        sock.close()

    threadId = input("Please enter the value of threadId: ")
    try:
        threadId = int(threadId)
        config.threadId = threadId
    except ValueError:
        print("The input values must be integers.")
        sys.exit(1)
    
    return index,payload_message

class Message_Result:
    def __init__(self, payload, fields, boundaries, field_types, field_funcs):
        self.payload = payload
        self.fields = fields
        self.boundaries = boundaries
        self.field_types = field_types
        self.field_funcs = field_funcs

def MonitorAnalysis(index: int, payload_message:list):


    #baseline res
    Polyglot_length_Res = [None] *index
    Polyglot_command_Res = [None] *index
    Polyglot_separator_Res = [None] *index
    Polyglot_Syntax = {}
    AutoFormat_ftrees = {}
    Tupni_Syntax = {}

    #settings
    baseline_mode = config.baseline_mode
    threadId = config.threadId
    ip = config.ip
    port = config.port

    message_Result = [None] * index
    message_Used = [None] * index
    Pre_message_Result = [None] * index


    #Analysis every msg sample
    for i in range(index):
        print("\n\n+++++++++++++++++++++++ Msg {} +++++++++++++++++++++++".format(i))
        new_directory = f"../PUT_test/{i}_tmp_results/"
        with open(new_directory + "format.txt", 'r') as f:
            lines = f.readlines()
        matching_lines = [line for line in lines if re.match("^\[Message\].*", line)]
        recordNums = len(matching_lines)

        if baseline_mode == "oa" or baseline_mode == "ba" or baseline_mode == "all":

            if baseline_mode == "oa" or baseline_mode == "ba":
                fields, field_Types, field_Functions, used_fields = Separator.AllAnalysis(recordNums, new_directory,payload_message[i])
            


            message_Used[i] = used_fields
            

            boundaries = set()
            msg_len = len(payload_message[i])
            boundaries.add(-1)
            boundaries.add(msg_len-1)
            add_fields = []
            
            boundary_2 = -1
            for field in fields:
                boundary_1 = int(field.split(',')[0])-1
                boundaries.add(boundary_1)

                f_i = ','.join(str(i) for i in range(boundary_2+1, boundary_1+1))
                print(f"add_field:{f_i}")
                if len(f_i)>0 :
                    add_fields.append(f_i)

                boundary_2 = int(field.split(',')[-1])
                boundaries.add(boundary_2)
            if boundary_2 < msg_len-1:
                f_i = ','.join(str(i) for i in range(boundary_2+1, msg_len))
                if len(f_i)>0 :
                    add_fields.append(f_i)
            
            for add_field in add_fields:
                if add_field not in fields:
                    fields.append(add_field)
                
            # print(f"add_fields:{add_fields}")

            boundaries = sorted(list(boundaries))
#
            message_Result[i] = Message_Result(payload_message[i], fields, boundaries, field_Types,field_Functions)

            #print the BinPRE's results on the Message i
            print(f"payload_message: {message_Result[i].payload}")
            print(f"fields: {message_Result[i].fields}")
            print(f"boundaries: {message_Result[i].boundaries}")
            print(f"field_Types: {message_Result[i].field_types}")
            print(f"field_Functions: {message_Result[i].field_funcs}")
            



        elif baseline_mode == "bo":
            Polyglot_length, Polyglot_keyword,Polyglot_separator,Polyglot_combined_format,AutoFormat_ftree,Tupni_format = Separator.AllAnalysis(recordNums, new_directory,payload_message[i])
            Polyglot_length_Res[i] = Polyglot_length
            Polyglot_command_Res[i] = Polyglot_keyword
            Polyglot_separator_Res[i] = Polyglot_separator
            Polyglot_Syntax[i] = Polyglot_combined_format
            AutoFormat_ftrees[i] = AutoFormat_ftree
            Tupni_Syntax[i] = Tupni_format


    
    
    if baseline_mode == "oa" or baseline_mode == "ba" or baseline_mode == "all":

        '''Semantic Refinment: Clustering & Type & Funcs'''

        for i in range(index):
            Pre_message_Result[i] = copy.deepcopy(message_Result[i])
        print(f"Pre_message_Result:{Pre_message_Result[0].field_types}")

        message_Result = Corrector.Validation(message_Result,payload_message)
        print(f"message_Result:{message_Result[0].field_types}")
        print(f"Pre_message_Result:{Pre_message_Result[0].field_types}")

        
        '''Evaluation & Results Printing -- BinPRE'''
        
        Average_Accr, F1_score, Average_Perf = BinPREEvaluator(payload_message, Pre_message_Result, message_Result, config.commandOffset, message_Used)
        no_Semantic_Average_Pre, no_Semantic_Average_Rec, no_Semantic_F1_score, Semantic_Average_Pre, Semantic_Average_Rec, Semantic_F1_score = BinPRE_Semantic_Types_Evaluator(payload_message, Pre_message_Result, message_Result, config.commandOffset)
        no_Function_Average_Pre, no_Function_Average_Rec, no_Function_F1_score, Function_Average_Pre, Function_Average_Rec, Function_F1_score = BinPRE_Semantic_Functions_Evaluator(payload_message, Pre_message_Result, message_Result, config.commandOffset)

        print(f"\n\n\n********* [Summary-{config.protocol_name}]: BinPRE Format Extraction *********")
        print(f"Average_Accr:{Average_Accr}")
        # print(f"Average_Pre:{Average_Pre}")
        # print(f"Average_Rec:{Average_Rec}")
        print(f"F1-score:{F1_score}")
        print(f"Average_Perf:{Average_Perf}")
        print(f"\n-----------------")

        print(f"\n********* [Summary-{config.protocol_name}]: BinPRE(no refine) Semantic-Types Inference *********")
        print(f"Average_Pre:{no_Semantic_Average_Pre}")
        print(f"Average_Rec:{no_Semantic_Average_Rec}")
        print(f"F1_score:{no_Semantic_F1_score}")


        print(f"\n********* [Summary-{config.protocol_name}]: BinPRE#(refinement) Semantic-Types Inference *********")
        print(f"Average_Pre:{Semantic_Average_Pre}")
        print(f"Average_Rec:{Semantic_Average_Rec}")
        print(f"F1_score:{Semantic_F1_score}")

        print(f"\n-----------------")

        print(f"\n********* [Summary-{config.protocol_name}]: BinPRE(no refine) Semantic-Functions Inference *********")
        print(f"Average_Pre:{no_Function_Average_Pre}")
        print(f"Average_Rec:{no_Function_Average_Rec}")
        print(f"F1_score:{no_Function_F1_score}")

        print(f"\n********* [Summary-{config.protocol_name}]: BinPRE#(refinement) Semantic-Functions Inference *********")
        print(f"Average_Pre:{Function_Average_Pre}")
        print(f"Average_Rec:{Function_Average_Rec}")
        print(f"F1_score:{Function_F1_score}")
    
    if baseline_mode == "bo" or baseline_mode == "all":

        '''Evaluation & Results Printing -- Polyglot, AutoFormat, Tupni'''

        PolyglotEvaluator(payload_message,Polyglot_Syntax,config.commandOffset)
        Autoformat_syntaxRes = AutoFormatEvaluator(payload_message,config.commandOffset,AutoFormat_ftrees)
        TupniEvaluator(payload_message,Tupni_Syntax,config.commandOffset)
    
        Print_bo_Res(payload_message, Polyglot_Syntax, Polyglot_length_Res, Polyglot_command_Res, Autoformat_syntaxRes, Tupni_Syntax)
        
        Polyglot_SemanticEvaluator(payload_message, Polyglot_length_Res, Polyglot_command_Res, Polyglot_separator_Res, config.commandOffset)

        
def main():
    start_time = time.time()
    if config.evaluation_mode == "oa":
        with open(config.Evaluation_Res, 'w') as f:
            f.truncate()
    if config.evaluation_mode == "bo":
        with open(config.Evaluation_bo_Res, 'w') as f:
            f.truncate()

    index,payload_message = SendInputMsg()

    MonitorAnalysis(index,payload_message)

    total_time = time.time()-start_time
    print("\nTotal Analyze Time:{}".format(total_time))



main()