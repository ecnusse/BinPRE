#-*- coding:utf-8 -*-

import pydot
from collections import OrderedDict
import sys
from collections import defaultdict
import re
import subprocess
import socket
import random
import os
import shutil
import time
import string
import config
from multiprocessing import Process
from multiprocessing import Process, Queue

from Baseline import *

semantic_result_dir = ""


   

def LoopAnalyzer4(curr_fi,loop_field_log):
    for loop_f in loop_field_log:
        loop_f = loop_f.strip(',').split(',')
        if(len(loop_f)>3 and int(loop_f[-1])==int(curr_fi.split(',')[0])-1):
            return 1
    return 0

def LoopAnalyzer5(loops,inst_field,curr_fi,loop_field_log):
    for loop_f in loop_field_log:
        if(curr_fi in loop_f):
            return 1
    return 0

def Cmp_ConsecutiveValue(cmp_elements):

    sorted_elements = sorted(int(element, 16) for element in cmp_elements)

    are_adjacent = all(sorted_elements[i] + 1 == sorted_elements[i+1] for i in range(len(sorted_elements) - 1))

    return are_adjacent

def Cmp_ConsecutiveBytes(curr_content, hashmap2):
    if len(curr_content)>1:
        return False
    if len(curr_content)==1:
        curr_content = hex(ord(curr_content))
    if len(curr_content)==0:
        curr_content = "0x0"
    print(f"cmpcurr_content:{curr_content}")
    if curr_content not in hashmap2:
        return False
    cmpBytes = hashmap2[curr_content]
    for element in cmpBytes:
        print(f"element:{element}")
        if (',' in element) or (';' in element):
            return False
    integer_list = list(map(int, cmpBytes))
    sorted_integer = sorted(integer for integer in integer_list)
    print(f"cmpBytes:{sorted_integer}")

    are_adjacent = all(sorted_integer[i] + 1 == sorted_integer[i+1] for i in range(len(sorted_integer) - 1))

    return are_adjacent



def Semantic_TypeFunc_Inference(groups_res, hashmap1, hashmap2, loops,cmp_true,cmpjmp,cmpjmp_func,inst_field,loop_field_log,addsub, addop, shrshl,lengthlog,payload_message):
    semantic_Types = config.semantic_Types
    semantic_Functions = config.semantic_Functions


    field_Types = {}
    field_Functions = {}

    '''Pre-Processing'''
    #add_sub related instruction info
    hashmap = {}
    for item,item2 in addsub:
        nums = item2.split(';')
        if ';' not in item:
            if item not in hashmap:
                hashmap[item] = 0
            hashmap[item] = hashmap[item]+1
        else:
            item_a = item.split(';')[0]
            item_b = item.split(';')[-1]
            if item_a not in hashmap:
                hashmap[item_a] = 0
            hashmap[item_a] = hashmap[item_a]+1
            if item_b not in hashmap:
                hashmap[item_b] = 0
            hashmap[item_b] = hashmap[item_b]+1

    #taint_to_taint related instruction info
    compare_Between_Taints = {}
    for key in list(hashmap1.keys()):
        if key.count(';')>0:
            key1 = key.split(';')[0]
            key2 = key.split(';')[-1]
            if key1 not in compare_Between_Taints:
                compare_Between_Taints[key1] = []
            compare_Between_Taints[key1].append(key2)
            if key2 not in compare_Between_Taints:
                compare_Between_Taints[key2] = []
            compare_Between_Taints[key2].append(key1)
    
    #shrshl related instruction info
    shrshl_Value = {}
    for f,value in shrshl:
        if f not in shrshl_Value:
            shrshl_Value[f] = set()
        shrshl_Value[f].add(value)

    #cmp_jmp related instruction info within loop 
    length_results = set()
    for instruction1, instruction2 in cmpjmp:
        content_1 = instruction1.strip().split('\t')
        content_2 = instruction2.strip().split('\t')
        thread = int(content_1[1])
        if thread != config.threadId: continue
        tag = content_1[0]
        head = content_1[0].strip("CMP+JUMP-Instruction").split(",")
        addr, inst0 = head[0].split(':')
        addr = int(addr, 16)
        head2 = content_2[0].strip("CMP+JUMP_NEXT-Instruction : ")
        jumpaddr = head2.strip(' ').split(' ')[-1]
        jumpaddr = int(jumpaddr, 16)
        flag1 = 0
        flag2 = 0
        for loopstart,loopend in loops:
            loopstart = int(loopstart,16) 
            loopend = int(loopend,16)
            if(addr>=loopstart and addr<loopend):
                flag1 = 1
            if(jumpaddr>=loopstart and jumpaddr<loopend):
                flag2 = 1
            if(flag1==1 and flag2==0):
                length_results.add(content_1[2].strip(';')) 

    
    '''Semantic Inference based on the behavior of each field'''
    
    fields = []
    used_fields = []
    for curr_fi in groups_res:
        print("\t--Curr Field:{}".format(curr_fi))
        fields.append(curr_fi)
        used_fields.append(curr_fi)
        fi_types = []
        fi_funcs = []
        
        flag_in = 0
        for i_f in inst_field:
            if i_f.field == curr_fi:
                flag_in = 1
                break

        '''Semantic Type Inference: Static, Group, String, Bit Field, Bytes'''

        curr_start = int(curr_fi.split(',')[0])
        curr_end = int(curr_fi.split(',')[-1])
        curr_content = payload_message[curr_start:curr_end+1]

        if curr_end > curr_start:
            string_content = bytes(payload_message[curr_start:curr_end])
            is_string = True
            try:
                decoded_string = string_content.decode()  
                for char in decoded_string:
                    if not (char.isalpha() or (char in ['.','_']) or (type(char) not in [int])) :
                        print(f"special:{char}")
                        is_string = False
            except UnicodeDecodeError as e:
                is_string = False
                is_valid_filename = False
            if is_string: 
                is_valid_filename = all(char not in ['/', '\\', ':', '*', '?', '"', '<', '>', '|'] for char in curr_content)
        else:
            is_string = False
            is_valid_filename = False


        real_fi = curr_fi
        # 'Bytes'

        if(flag_in == 0):
            if len(curr_fi.split(','))>2:
                if LoopAnalyzer5(loops,inst_field,curr_fi,loop_field_log)==1:
                    fi_types.append(semantic_Types[4])
                else:
                    curr_fi = curr_fi.split(',')[0]
            else:
                print("error Semantic_TypeFunc_Inference")
        

        # 'Static'
        if (curr_fi in cmp_true) and (len(hashmap1[curr_fi])==1):
            fi_types.append(semantic_Types[0])
        
        # 'Group'
        if curr_fi in hashmap1 and (len(hashmap1[curr_fi])>2):
            fi_types.append(semantic_Types[1])

        # 'Integer'
        if (curr_fi in hashmap) or \
            (curr_fi in hashmap1 and len(hashmap1[curr_fi])>2 and (Cmp_ConsecutiveValue(hashmap1[curr_fi])==1)) or \
            (curr_fi in shrshl_Value):
                fi_types.append(semantic_Types[3])
        
        if curr_fi in compare_Between_Taints:
            for ele in compare_Between_Taints[curr_fi]:
                if ele in field_Types and (semantic_Types[3] in field_Types[ele]):
                    if semantic_Types[3] not in fi_types:
                        fi_types.append(semantic_Types[3])
        # 'String'
        
        if is_string and ((flag_in==0 and real_fi.count(',')>=2) or (flag_in==1 and curr_fi.count(',')>2)):

            fi_end = int(real_fi.split(',')[-1])
            fi_content = bytes(payload_message[fi_end])

            if Cmp_ConsecutiveBytes(fi_content, hashmap2):
                fi_types.append(semantic_Types[2])
        
        

        if len(fi_types) == 0:
            fi_types.append(semantic_Types[0])

        if config.text_flag == 0:
            if semantic_Types[2] in fi_types:
                fi_types.remove(semantic_Types[2])
            


        '''Semantic Function Inference: Command, Length, Delim, CheckSum, Aligned, Filename'''
        
        # Length
        if (curr_fi in lengthlog) or (curr_fi in hashmap) or (curr_fi in length_results):
            if semantic_Types[3] in fi_types:
                fi_funcs.append(semantic_Functions[1])
        
        # Command
        if curr_fi in cmpjmp_func:
            if semantic_Types[1] in fi_types:
                fi_funcs.append(semantic_Functions[0])
        
        # CheckSum
        if LoopAnalyzer4(curr_fi,loop_field_log):
                fi_funcs.append(semantic_Functions[3])

        

        # filename
        if is_valid_filename:
            if semantic_Types[2] in fi_types:
                fi_funcs.append(semantic_Functions[5])
        
        # Delim
        if (curr_fi in length_results) or \
            ((curr_fi in cmp_true) and (len(hashmap1[curr_fi])==1)) or \
            ((curr_fi in cmp_true) and Cmp_ConsecutiveBytes(curr_content, hashmap2)):
            if semantic_Types[1] in fi_types or semantic_Types[0] in fi_types:
                fi_funcs.append(semantic_Functions[2])
        
        # Aligned/Delim
        
        if (curr_fi not in hashmap1) and (curr_fi not in hashmap) and (curr_fi not in shrshl):
            if config.text_flag == 0:
                if fi_types==[semantic_Types[0]] or (semantic_Types[4] in fi_types):
                    fi_funcs.append(semantic_Functions[4])
            if config.text_flag == 1:
                if fi_types==[semantic_Types[0]]:
                    fi_funcs.append(semantic_Functions[2])
        
        
        if config.text_flag == 0:
            if semantic_Functions[2] in fi_funcs:
                fi_funcs.remove(semantic_Functions[2])
            if semantic_Functions[5] in fi_funcs:
                fi_funcs.remove(semantic_Functions[5])
        
        
        
        if config.text_flag == 1:
            if semantic_Functions[1] in fi_funcs:
                fi_funcs.remove(semantic_Functions[1])
        

        field_Types[real_fi] = fi_types
        field_Functions[real_fi] = fi_funcs


    return fields, field_Types, field_Functions, used_fields





def Semantix(threadId, sizeofTaint, groups_res, hashmap1, hashmap2, loops,cmp_true,cmpjmp,cmpjmp_func,inst_field,loop_field_log, msg_content, addsub, addop, shrshl,lengthlog,payload_message):
    
    fields, field_Types, field_Functions, used_fields = Semantic_TypeFunc_Inference(groups_res, hashmap1, hashmap2, loops,cmp_true,cmpjmp,cmpjmp_func,inst_field,loop_field_log, addsub, addop, shrshl,lengthlog,payload_message)


    return fields, field_Types, field_Functions, used_fields
    

