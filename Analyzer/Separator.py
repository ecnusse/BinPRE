# -*- coding:utf-8 -*-


import re
import Speculator
import matplotlib

import Similarity
import sys
import time
from Baseline import *
import config

from AAA_Evaluation import *

# =====USER's OPTION======
Protocol_type = 'b'  # 'b'/'t':binary/text


# =====Analyzer Related VALUE DEFINE========
result_dir = ""

sizeofTaint = 0

Result_Format = set()
inst_offsetList = []


FunctionsChain = []
inst_list = []
inst_field = []
offset_instlog = {}
field_instlines = {}
msg_content = ""

"semantic"
hashmap1 = {}  
hashmap2 = {}  
cmp_true = set()
cmpjmp_func ={}
loop_insts = []
lengthlog = []
addsub = []
addop = []
shrshl = []
cmpjmp = []
taintlog = []  
taint_func = []
loop_field_log = []
lines = []

# [Loop deduplication]
loops = []  # 2-tuples（loopstartaddr,loopsize)
groupstartaddr = 0
groupendaddr = 0

groups_res = []

def file_processing():
    with open(result_dir + 'semantics.txt', mode='w', encoding='utf-8') as semantic:
        semantic.seek(0)
        semantic.truncate()
        semantic.close()

    with open(result_dir + 'tree.txt', mode='w', encoding='utf-8') as t:
        t.seek(0)
        t.truncate()
        t.close()

    with open(result_dir + 'inst.txt', mode='w', encoding='utf-8') as i:
        i.seek(0)
        i.truncate()
        i.close()

    with open(result_dir + 'AAA_ourApproach.txt', mode='w', encoding='utf-8') as o:
        o.seek(0)
        o.truncate()
        o.close()

    with open(result_dir + "info.txt", "r") as f:
        global lines 
        lines = f.readlines()  # info.txt

    with open(result_dir + "loops.txt", "r") as l:
        global loopsinfo
        loopsinfo = l.readlines()  # loops.txt

class Offset_Instruction(object):
    def __init__(self, o, c, s, l, inst):
        self.offset = o
        self.content = c
        self.stack = s
        self.address = l
        self.inst = inst

class Field_Instruction(object):
    def __init__(self, f, s, l, inst, line):
        self.field = f
        self.stack = s
        self.address = l
        self.inst = inst
        self.line = line


def write_to_file_AAA(data):
    with open(result_dir + 'AAA_ourApproach.txt', 'a', encoding='utf-8') as o:
        o.write(data + '\n')
    o.close()


def read_from_format(lineIndex):
    with open(result_dir + 'format.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()

        line = lines[lineIndex].strip()
        msg_content = line.split(':')[-1]  

        pattern = r'size\s+(\S+):'
        match_list = re.findall(pattern, line)
        if match_list:
            size_char = match_list[0]
        else:
            size_char = None

    f.close()
    return size_char,msg_content



def Pre_Processing(msgNums, threadId):
    matplotlib.use('agg')
    file_processing()

    global sizeofTaint, Result_Format, inst_offsetList, FunctionsChain, inst_list,\
           inst_field, offset_instlog, field_instlines, msg_content, hashmap1, hashmap2,\
           cmp_true, cmpjmp_func, loop_insts, lengthlog, addsub, addop, cmpjmp, taintlog,\
           taint_func, loop_field_log, lines, loops, groupstartaddr, groupendaddr,shrshl
   
    # =============Pre-Processing===============
    
    # determine the size of current message with 'format.txt'
    for i in range(msgNums):
        size_char,tmp_content = read_from_format(i)
        if size_char == None:
            break
        sizeofTaint = max(sizeofTaint, int(size_char, 16))
        if sizeofTaint == int(size_char, 16):
            size_char,msg_content = read_from_format(i)
            x = size_char.split(":	")

    # [LOOP Processing]
    for i in range(len(loopsinfo)):
        loopsinfo[i] = loopsinfo[i].strip('\n')
        if not loopsinfo[i].startswith("LOOP"):
            continue
        loopsinfo[i] = loopsinfo[i].strip('LOOP ')
        addr_start = loopsinfo[i].split('\t')[1]
        loopstart = int(addr_start, 16)
        loop_size = int(loopsinfo[i].split('\t')[-1], 16)
        loopend = loopstart + loop_size
        if i == 0:
            groupstartaddr = loopstart
            groupendaddr = loopend
        if (loopstart == groupendaddr):
            groupendaddr = loopend
        else:
            if i != 0:
                loops.append((hex(groupstartaddr), hex(groupendaddr)))

            groupstartaddr = loopstart
            groupendaddr = loopend
        if (i == len(loopsinfo) - 1):
            config.write_to_file(result_dir, "{}: {}".format(groupstartaddr, groupendaddr))
            loops.append((hex(groupstartaddr), hex(groupendaddr)))

    # [Instruction Processing]
    for i_line in range(len(lines)):
        curr_line = lines[i_line]
        content = lines[i_line].strip().split('\t')
        tag = content[0]

        if tag.startswith("Instruction") or tag.startswith("CMP+JUMP-Instruction"):
            thread = int(content[1])
            if config.restartFlag!= 1 and thread != threadId:
                continue
            if tag.startswith("CMP+JUMP-Instruction"):
                head = content[0].replace("CMP+JUMP-Instruction ",'').split(",")
                a = lines[i_line]
                while not lines[i_line].startswith("CMP+JUMP_NEXT-Instruction"):
                    i_line = i_line + 1
                b = lines[i_line]
                cmpjmp.append((a, b))
                continue
            else:
                head = content[0].replace("Instruction ",'').split(",")
            addr, inst0 = head[0].split(':')
            addr = int(addr, 16)  
            assembly = inst0.strip().split()[0]  

            if len(head) == 1:
                read = None
                isnum = False
            else: 
                read = head[1].strip() 
                isnum = read.startswith("0x")

            data = content[2]
            iswrite, isread = True, True
            if data.count(';') == 0:  
                isread = False
            elif data.startswith(';'):
                iswrite = False
            
            if isnum: 
                writev = content[3] 
                readv = read  
            elif content[3].count(';') > 0:  
                writev, readv = content[3].split(';')  
            else:  
                readv = content[3]

            if assembly.startswith("cmp"): 
                data = data.strip(";")  
                if isread:  
                    cmpobj = "{}".format(writev)
                if iswrite:  
                    cmpobj = readv  
                    if not isnum:
                        cmpobj = "{}".format(readv)

                if data not in hashmap1:
                    hashmap1[data] = set()
                if cmpobj not in hashmap2:
                    hashmap2[cmpobj] = set()
                hashmap1[data].add(cmpobj)
                hashmap2[cmpobj].add(data)


                cmpNumlog = content[-1]
                cmp_flag = 0
                if content[-1].count(';') == 0:
                    if content[-1] == cmpobj:
                        cmp_true.add(data)
                        cmp_flag = 1
                    
                    if len(cmpjmp):
                        if (int(content[-1][2:], 16) < int(cmpobj[2:], 16) and (
                                " jl " in cmpjmp[-1][1] or " jnge " in cmpjmp[-1][1])) or \
                                (int(content[-1][2:], 16) > int(cmpobj[2:], 16) and (
                                        " jg " in cmpjmp[-1][1] or " jnle " in cmpjmp[-1][1])) or \
                                (int(content[-1][2:], 16) >= int(cmpobj[2:], 16) and (
                                        " jnl " in cmpjmp[-1][1] or " jge " in cmpjmp[-1][1])) or \
                                (int(content[-1][2:], 16) <= int(cmpobj[2:], 16) and (
                                        " jle " in cmpjmp[-1][1] or " jng " in cmpjmp[-1][1]))or \
                                (int(content[-1][2:], 16) != int(cmpobj[2:], 16) and (
                                        " jnz " in cmpjmp[-1][1] or " jne " in cmpjmp[-1][1])):
                            cmp_true.add(data)
                            cmp_flag = 1
                else:
                    left_cmp = cmpNumlog.split(';')[0]
                    right_cmp = cmpNumlog.split(';')[1]
                    if (left_cmp == right_cmp):
                        cmp_true.add(data)
                        cmp_flag = 1
                if cmp_flag == 1:
                    pre_i_line = i_line
                    if config.restartFlag != 1:
                        exitfunc_str = "Function\t{}\texit".format(threadId)
                        enterfunc_str = "Function\t{}\tenter".format(threadId)
                    else:
                        exitfunc_str = "Function\t{}\texit".format(thread)
                        enterfunc_str = "Function\t{}\tenter".format(thread)

                    while (i_line + 1)<len(lines) and not lines[i_line + 1].startswith(exitfunc_str):
                        if lines[i_line + 1].startswith(enterfunc_str):
                            if not (data in cmpjmp_func):
                                cmpjmp_func[data] = set()
                            cmpjmp_func[data].add(lines[i_line + 1].split('\t')[3]) 
                            break
                        i_line = i_line + 1
                    i_line = pre_i_line
            
            if assembly.startswith("add") or assembly.startswith("sub"):
                addsub.append((content[2], content[3]))
                if assembly.startswith("add"):
                    addop.append((content[2], content[3]))
            
            if assembly.startswith("shr") or assembly.startswith("shl"):
                shrshl.append((content[2], content[0].split(', ')[-1]))


            for d in data.split(';'):
                if not d: continue

                curr_stack = FunctionsChain[:]
                curr_inst = Offset_Instruction(d, "", curr_stack, addr, content)
                curr_inst.content = ""

                out_bound_flag = 0
                if d not in field_instlines:
                    field_instlines[d] = set()
                field_instlines[d].add(lines[i_line]) 

                for i in d.split(','):
                    i = int(i)
                    if (i >= sizeofTaint):
                        out_bound_flag = 1
                        break  
                    curr_inst.offset = i
                    curr_inst.content = curr_inst.content + msg_content.split(' ')[i].strip('(').strip(')') + " "
                    
                    offset_instlog[i] = Offset_Instruction(curr_inst.offset, curr_inst.content, curr_inst.stack,
                                                            curr_inst.address, content[0])
                    inst_list.append(
                        Offset_Instruction(curr_inst.offset, curr_inst.content, curr_inst.stack, curr_inst.address,
                                            content[0]))

                if out_bound_flag == 1:
                    break

                inst_field.append(
                    Field_Instruction(d, curr_inst.stack, curr_inst.address, content[0], curr_line.split(": ")[1]))
                Result_Format.add(d)
                if (len(inst_offsetList) == 0) or (len(inst_offsetList) > 0 and inst_offsetList[-1] != d):
                    inst_offsetList.append(d)

        elif tag.startswith("Function"):
            thread = int(content[1])
            if config.restartFlag != 1 and thread != threadId: continue
            if len(content)<4:#useless info
                continue
            FunctionsChain.append((content[3], str(content[2])))
            if content[2] == "enter" and (content[3].count("str") > 0 or content[3].count("len") > 0):
                paras = content[4].strip('()').split(',')
                for para_addr in paras:
                    para_addr = int(para_addr, 16)
                    for taint_start, taint_end in taintlog:
                        if para_addr >= taint_start and para_addr < taint_end:
                            taint_func.append(para_addr)



        elif tag.startswith("LENGTH"):
            lengthlog.append(content[1])
        elif tag.startswith("Taint"):
            taintaddr, taintsize = content[1].strip('(').strip(')').split(", ")
            taintstart = int(taintaddr, 16)
            taintend = taintstart + int(taintsize, 16)
            taintlog.append((taintstart, taintend))
            

def SyntaxAnalyzer():

    global sizeofTaint, Result_Format, inst_offsetList, FunctionsChain, inst_list,\
           inst_field, offset_instlog, field_instlines, msg_content, hashmap1, hashmap2,\
           cmp_true, cmpjmp_func, loop_insts, lengthlog, addsub, addop, cmpjmp, taintlog,\
           taint_func, loop_field_log, lines, loops, groupstartaddr, groupendaddr, groups_res, shrshl


    #######  Intra- and Inter- Instruction Analysis

    group = list(range(sizeofTaint))

    # Intra-Instruction Analysis
    single_inst = set()  
    for i_f in inst_field:
        off_start = int(i_f.field.split(',')[0])
        off_end = int(i_f.field.split(',')[-1])
        if (off_start >= group[0] and off_end <= group[-1]):
            single_inst.add(i_f.field)
    single_inst = sorted(list(single_inst), key=lambda x: config.compare_key_1(x), reverse=True)
    single_inst = sorted(single_inst, key=config.compare_key_3)
    print(f"Intra-Instruction Analysis Syntax——Res:{single_inst}")

    # Inter-Instruction Analysis
    In_group_Res = []  

    while In_group_Res != single_inst:  

        if len(In_group_Res) != 0:  
            single_inst = In_group_Res  
            In_group_Res = []

        # collect all field candidates
        single_i = 0
        while single_i < len(single_inst):
            if (single_i + 1 < len(single_inst) and 
                int(single_inst[single_i].split(',')[-1]) < int(single_inst[single_i + 1].split(',')[0])):
                In_group_Res.append(single_inst[single_i])
            elif (single_i + 1 == len(single_inst)):  
                In_group_Res.append(single_inst[single_i])

            elif (single_i + 1 < len(single_inst) and 
                  int(single_inst[single_i].split(',')[-1]) >= int(single_inst[single_i + 1].split(',')[0])):
                curr_cmp = single_inst[single_i]
                while (single_i + 1 < len(single_inst) and 
                       int(curr_cmp.split(',')[-1]) >= int(single_inst[single_i + 1].split(',')[0])):
                    single_i = single_i + 1
                In_group_Res.append(curr_cmp)

            single_i = single_i + 1

    single_inst = sorted(list(single_inst), key=lambda x: config.compare_key_1(x), reverse=True)
    single_inst = sorted(single_inst, key=config.compare_key_3)


    if (len(In_group_Res) == 1):
        groups_res.append(In_group_Res[0])

    In_group_Res = set() 
    while list(In_group_Res) != single_inst:  
        if len(In_group_Res) != 0:  
            single_inst = list(In_group_Res)  
            In_group_Res = set()
        single_i = 0
        while single_i < len(single_inst):
            tmp_res = set()
            ss = ""
            if (single_i + 1 < len(single_inst) and int(single_inst[single_i].split(',')[-1]) + 1 < int(
                    single_inst[single_i + 1].split(',')[0])):
                In_group_Res.add(single_inst[single_i])
            while (single_i + 1 < len(single_inst) and int(single_inst[single_i].split(',')[-1]) + 1 == int(
                    single_inst[single_i + 1].split(',')[0])):
                cmp_a = single_inst[single_i]
                cmp_b = single_inst[single_i + 1]
                cmpa_insts = []
                cmpb_insts = []
                cmp_insts = []
                single_i = single_i + 1
                chain = []
                addr = ""
                similarity_score = 0
                pre_l = inst_field[0]
                for l in inst_field:

                    if (l.field == cmp_a or l.field == cmp_b):
                        
                        if (addr != l.address and chain != l.stack):
                            addr = l.address
                            chain = l.stack
                            
                        elif (addr == l.address and 
                              pre_l.address == l.address and 
                              l.field == cmp_b and 
                              pre_l.field == cmp_a):
                            similarity_score = 1

                    if (l.field == cmp_a):  
                        cmpa_insts.append(l.inst.split(': ')[1].split(' ')[0])
                        cmp_insts.append(cmp_a + "_" + l.inst)
                    if (l.field == cmp_b):  
                        
                        cmpb_insts.append(l.inst.split(': ')[1].split(' ')[0])
                        cmp_insts.append(cmp_a + "_" + l.inst)

                    pre_l = l
                '''similarity calculation'''
                if (len(cmpa_insts) != 0 and len(cmpb_insts) != 0):
                    similarity_score = Similarity.needleman_wunsch(cmpa_insts, cmpb_insts)

                if (cmp_b.count(',') > 0 and cmp_a.count(',') > 0):
                    flaga = 0
                    for string in cmpa_insts:
                        if not string.startswith("mov"):
                            flaga += 1
                    flagb = 0
                    for string in cmpb_insts:
                        if not string.startswith("mov"):
                            flagb += 1
                    if (flaga == 0 and flagb == 0):
                        similarity_score = 0

                print(f"similarity_score:{similarity_score}")
                if ((config.baseline_mode == 'oa') and (similarity_score >= config.threshold)):  
                    if ss == "":
                        ss = str(cmp_a)
                    ss = ss + "," + str(cmp_b)
                else:
                    if ss != "":
                        In_group_Res.add(ss)
                        ss = ""
                    else:
                        tmp_res.add(cmp_a)
                    if single_i + 1 == len(single_inst) or int(single_inst[single_i + 1].split(',')[0]) > int(
                            single_inst[single_i].split(',')[-1]) + 1:
                        tmp_res.add(cmp_b)

            if ss != "":
                In_group_Res.add(ss)

            if (ss == "" and single_i + 1 == len(single_inst)):
                In_group_Res.add(single_inst[single_i])

            single_i = single_i + 1
            for t in tmp_res:
                In_group_Res.add(t)

        if (len(In_group_Res) == 0):
            In_group_Res = single_inst
        In_group_Res = sorted(list(In_group_Res), key=lambda x: config.compare_key_1(x), reverse=True)
        In_group_Res = sorted(In_group_Res, key=config.compare_key_3)

    for ele in In_group_Res:
        groups_res.append(ele)

    groups_res = sorted(list(groups_res), key=lambda x: config.compare_key_1(x), reverse=True)
    groups_res = sorted(groups_res, key=config.compare_key_3)
    
    write_to_file_AAA("=================Our Aprroach Result================")
    write_to_file_AAA("\n\t[Format Extraction]")
    write_to_file_AAA("\t\t{}".format(groups_res))


def Structrued_Analysis(sizeofTaint, inst_list, inst_field, loops, result_dir):
    loop_field_log = set()

    if not inst_list:
        return

    loops_offset = {}

    pre_loop = 0000
    pre_inst = inst_list[-1]
    
    r = {}  
    Qi = []
    for inst in inst_list:  
        for loopstart, loopend in loops:
            loopstart = int(loopstart, 16)
            loopend = int(loopend, 16)
            if (inst.address < loopend and inst.address >= loopstart):
                curr_loop = loopstart
                if pre_loop == curr_loop and (inst.address > pre_inst.address or (
                        inst.address == pre_inst.address and inst.offset == pre_inst.offset)):

                    Qi.append(inst)
                else:

                    if str(pre_loop) not in r:
                        r[str(pre_loop)] = list()
                    r[str(pre_loop)].append(list(Qi))
                    Qi = []
                    Qi.append(inst)

                pre_loop = curr_loop
                pre_inst = inst
    for k, Q in list(r.items()):  
        if k == "0": continue
        Q_insts = {}
        for Qi in Q:  
            addrs = []
            for inst in Qi:
                addrs.append(inst.address)
            Q_insts.setdefault(tuple(addrs), set()).add(tuple(Qi))
        for addrs, Qis in list(Q_insts.items()):
            Structured = []
            if len(Qis) > 1:

                for Qi in Qis:
                    offsets = []
                    for inst in Qi:
                        offsets.append(inst.offset)
                    Structured.append(offsets)
            else:
                offsets = set()
                for inst in list(Qis)[0]:
                    offsets.add(inst.offset)
                Structured.append(offsets)
            curr_results = set()
            for eles in Structured:
                for ele in eles:
                    curr_results.add(ele)
            record = ""
            for item in curr_results:
                record += str(item) + ","
            config.write_to_file(result_dir, "\t" + record)
            loop_field_log.add(record)
            print(f"loop_field_log:{loop_field_log}")
    
    

    return loop_field_log


def reset_var():
    global sizeofTaint, Result_Format, inst_offsetList, FunctionsChain, inst_list,\
           inst_field, offset_instlog, field_instlines, msg_content, hashmap1, hashmap2,\
           cmp_true, cmpjmp_func, loop_insts, lengthlog, addsub, addop, cmpjmp, taintlog,\
           taint_func, loop_field_log, lines, loops, groupstartaddr, groupendaddr, groups_res,shrshl

    sizeofTaint = 0
    Result_Format = set()
    inst_offsetList = []
    FunctionsChain = []
    inst_list = []
    inst_field = []
    offset_instlog = {}
    field_instlines = {}
    msg_content = ""
    hashmap1 = {}  
    hashmap2 = {}  
    cmp_true = set()
    cmpjmp_func = {}
    loop_insts = []
    lengthlog = []
    addsub = []
    addop = []
    shrshl = []
    cmpjmp = []
    taintlog = []  
    taint_func = []
    loop_field_log = []
    lines = []
    loops = [] 
    groupstartaddr = 0
    groupendaddr = 0
    groups_res = []    


def AllAnalysis(msgNums, result_dir_input,payload_message):
    global result_dir
    result_dir = result_dir_input

    threadId = config.threadId
    baseline_mode = config.baseline_mode
    
    reset_var()
    
    Pre_Processing(msgNums, threadId)
    
    if baseline_mode == "bo":
        # =====Syntax Analyzer======[Polyglot, AutoFormat, Tupni]
        config.write_to_file(result_dir, "\n===============================")
        polyglot_results_update = FormatPrint_FLAT_Polyglot(sizeofTaint, Result_Format,result_dir)
        AutoFormat_ftree = FormatPrint_AutoFormat(sizeofTaint, inst_list, loops, offset_instlog, result_dir)

        Tupni_format = FormatPrint_Tupni(sizeofTaint, inst_list, inst_field, loops, result_dir)

        # =====Semantic Analyzer[Polyglot, AutoFormat, Tupni]======
        Polyglot_length,Polyglot_keyword,Polyglot_separator, Polyglot_variables = BaselineAnalysis(payload_message, result_dir, threadId, Protocol_type, hashmap1, hashmap2, sizeofTaint, list(cmp_true), lengthlog, addsub, addop, 
                                loops, cmpjmp, taint_func, taintlog)  

        Polyglot_length, Polyglot_keyword,Polyglot_separator,Polyglot_combined_format = Polyglot_Res(Polyglot_variables, polyglot_results_update, sizeofTaint, Result_Format, Polyglot_length, Polyglot_keyword, Polyglot_separator)
        
        return Polyglot_length, Polyglot_keyword,Polyglot_separator,Polyglot_combined_format,AutoFormat_ftree,Tupni_format
    
    elif baseline_mode == "oa" or baseline_mode == "ba":
        #============ Our Approach:[BinPRE] =======================

        SyntaxAnalyzer()
        loop_field_log = Structrued_Analysis(sizeofTaint, inst_list, inst_field, loops, result_dir)
        
        fields, field_Types, field_Functions, used_fields = Speculator.Semantix(threadId, sizeofTaint, groups_res, hashmap1, hashmap2, loops, cmp_true, cmpjmp, cmpjmp_func, inst_field,loop_field_log, msg_content,addsub, addop, shrshl,lengthlog,payload_message)
        

        
        return fields, field_Types, field_Functions, used_fields
    
