import re
import config

def custom_split_list(input_list, delimiters):
    result = []
    for input_string in input_list:
        regex_pattern = '|'.join(map(re.escape, delimiters))
        split_result = re.split(regex_pattern, input_string)
        split_result = [item.strip(',') for item in split_result if item]
        result = result + split_result
    return result

def Polyglot_Res(polyglot_variables, polyglot_results_update, sizeofTaint, Result_Format, Polyglot_length, Polyglot_keyword, Polyglot_separator):
    if Polyglot_separator is not None and len(Polyglot_separator)>0:
        Polyglot_combined_format = custom_split_list(polyglot_results_update, Polyglot_separator)
        
        if all(delimiter not in Polyglot_combined_format for delimiter in Polyglot_separator):
            Polyglot_combined_format += Polyglot_separator
    else:
        Polyglot_combined_format = polyglot_results_update
    
    var = []
    for variable in polyglot_variables:
        variable = variable.split(',')
        for byte in variable:
            var.append(byte)

    new_combined_format = []
    for field in Polyglot_combined_format:

        if (field.split(',')[0] not in var):
            new_combined_format.append(field)

    

    Polyglot_combined_format = new_combined_format
    
    for variable in polyglot_variables:
        Polyglot_combined_format.append(variable)

    Polyglot_combined_format = sorted(list(Polyglot_combined_format), key=lambda x: config.compare_key_1(x), reverse=True)
    Polyglot_combined_format = sorted(Polyglot_combined_format, key=config.compare_key_3)

    pre_e = -1
    uppdate = []
    for field in Polyglot_combined_format:
        f_s = int(field.split(',')[0])
        f_e = int(field.split(',')[-1])
        if f_s == (pre_e + 1):
            pre_e = f_e
            continue
        pre_e = pre_e + 1

        while pre_e < f_s :
            uppdate.append(str(pre_e))
            pre_e += 1

        pre_e = f_e
    Polyglot_combined_format += uppdate

    Polyglot_combined_format = sorted(list(Polyglot_combined_format), key=lambda x: config.compare_key_1(x), reverse=True)
    Polyglot_combined_format = sorted(Polyglot_combined_format, key=config.compare_key_3)

    
    end_index = int(Polyglot_combined_format[-1].split(',')[-1])

    print(f"end_index:{end_index}")
    print(f"sizeofTaint:{sizeofTaint}")

    while end_index < (sizeofTaint -1):
        end_index += 1
        
        Polyglot_combined_format.append(str(end_index))

    Polyglot_combined_format = set(Polyglot_combined_format)

    merged_list = []

    for item in Polyglot_combined_format:
        item_set = set(item.split(','))  
        overlapping_elements = set()  
        
        for existing_item in merged_list:
            existing_item_set = set(existing_item.split(','))
            if item_set.intersection(existing_item_set):
                overlapping_elements.update(existing_item_set)  
        
        if overlapping_elements:
            
            merged_element = ','.join(sorted(item_set.union(overlapping_elements), key=int))  
            merged_list = [existing_item for existing_item in merged_list if set(existing_item.split(',')).isdisjoint(overlapping_elements)]  
            merged_list.append(merged_element)  
        else:
            merged_list.append(item) 

    print(f"merged_list:{merged_list}")

    Polyglot_combined_format = merged_list
    
    Polyglot_combined_format = sorted(list(Polyglot_combined_format), key=lambda x: config.compare_key_1(x), reverse=True)
    Polyglot_combined_format = sorted(Polyglot_combined_format, key=config.compare_key_3)


    print("****************Polyglot********************")
    print("Polyglot_length: {}".format(Polyglot_length))
    print("Polyglot_keyword: {}".format(Polyglot_keyword))
    print("Polyglot_separator: {}".format(Polyglot_separator))
    print("==Fixed Field: {}".format(Result_Format))
    print("==variables: {}".format(polyglot_variables))
    print("Polyglot Combined Message Format: {}".format(Polyglot_combined_format))

    return Polyglot_length, Polyglot_keyword,Polyglot_separator,Polyglot_combined_format
    

def FormatPrint_FLAT_Polyglot(sizeofTaint, Result_Format,result_dir):

    if not Result_Format:
        return
    config.write_to_file(result_dir,"sizeofTaint: {}".format(sizeofTaint))
    config.write_to_file(result_dir," ")
    config.write_to_file(result_dir,"Format_[FLAT: polyglot]")

    Result_Format = sorted(Result_Format, key=lambda x: config.compare_key_1(x), reverse=True)
    Result_Format = sorted(Result_Format, key=config.compare_key_3)
    polyglot_results = []
    polyglot_results_update = []
    collect = set()
    for data in Result_Format:
        offsets = data.split(',')
        flag = 0
        for i in offsets:
            if i not in collect:
                collect.add(i)
            else:
                flag = 1
        if (flag == 0):
            polyglot_results.append(data)

    for element in polyglot_results:
        if (element.count(',') == 0 and int(element) >= sizeofTaint) \
            or (element.count(',') > 0 and any(int(i) > sizeofTaint for i in element.split(','))):
            continue
        polyglot_results_update.append(element)
        config.write_to_file(result_dir,"\t" + element)
        
    return polyglot_results_update



def Pre_Processing(msgNums, threadId):
    Msg_Res = ""
    matplotlib.use('agg')
    file_processing()

    global sizeofTaint, Result_Format, inst_offsetList, FunctionsChain, inst_list,\
           inst_field, offset_instlog, offset_instsChain,field_instlines, msg_content, hashmap1, hashmap2,\
           cmp_true, cmpjmp_func, loop_insts, lengthlog, addsub, addop, cmpjmp, taintlog,\
           taint_func, loop_field_log, lines, loops, groupstartaddr, groupendaddr,shrshl
   
    # =============Pre-Processing===============

    for i in range(msgNums):
        size_char,tmp_content = read_from_format(i)
        if size_char == None:
            break

        sizeofTaint = max(sizeofTaint, int(size_char, 16))
        
        if sizeofTaint == int(size_char, 16):

            size_char,msg_content = read_from_format(i)
            x = size_char.split(":	")
    Msg_Res =  msg_content
    print(f"msg_content:{msg_content}")

    print("SizeOfTaint:{}".format(sizeofTaint))

    offset_instsChain = {i: [] for i in range(sizeofTaint)}

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
                if Mode == 'H' or Mode == 'S':
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

                        offset_instsChain[i].append(content[0])  
                
                        
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
            if len(content)<4:
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
            
    
    return Msg_Res



def Seperator_Infer(payload_message, hashmap2, cmp_true):
    SeperatorFlag = 0
    Polyglot_separator = []
    for key in list(hashmap2.keys()):
        if(len(hashmap2[key])>=3):
            v = hashmap2[key]
            
            sorted_v = sorted(list(v), key=lambda x: config.compare_key_1(x), reverse=True)
            sorted_v = sorted(sorted_v, key=config.compare_key_3)

            pre_end = -1
            count = 1
            TrueFlag = 0
            
            for ele in sorted_v:
                if ele.count(';')>0:
                    continue
                    
                ele_start = int(ele.split(',')[0])
                ele_end = int(ele.split(',')[-1])
                if (pre_end + 1) == ele_start:
                    count += 1
                if ele in cmp_true:
                    TrueFlag = 1
                else:
                    TrueFlag = 0
                if count >= 3 and TrueFlag == 1:
                    if len(bytes(payload_message[ele_start: ele_end+1]))>1:
                        continue
                    if hex(ord(bytes(payload_message[ele_start: ele_end+1])))== key:
                        Polyglot_separator.append(ele)
                pre_end = ele_end

    
    print(f"Polyglot_Separator:{Polyglot_separator}")
    write_to_file(f"Polyglot_Separator:{Polyglot_separator}")

    return Polyglot_separator



def write_to_file(data):
    with open(semantic_result_dir + 'semantics.txt', 'a') as f:
        f.write(data + '\n')
    f.close()

def Keywords_Infer(protocol_type, hashmap1, cmp_true, Polyglot_separator):
    Polyglot_keyword = []

    write_to_file("KEYWORDs:")
    collect = set()
    for items in cmp_true:
        if items.count(';')>0:
            continue
        for i in items.split(','):
            collect.add(int(i))
    
    collect = sorted(collect)
    write_to_file(f"collect:{collect}")
    
    curr = []
    for i in range(len(collect)):
        curr.append(collect[i])

        if (i+1)<len(collect) and \
        ((collect[i] in Polyglot_separator) or (collect[i+1] > collect[i]+1)):
            Polyglot_keyword.append(','.join(str(j) for j in range(curr[0], curr[-1]+1)))
            curr = []
    Polyglot_keyword.append(','.join(str(j) for j in range(curr[0], curr[-1]+1)))

    write_to_file("Polyglot_keyword:\t{}".format(Polyglot_keyword))
    return Polyglot_keyword


def Seperator_Infer(payload_message, hashmap2, cmp_true):
    SeperatorFlag = 0
    Polyglot_separator = []
    for key in list(hashmap2.keys()):
        if(len(hashmap2[key])>=3):
            v = hashmap2[key]
            sorted_v = sorted(list(v), key=lambda x: config.compare_key_1(x), reverse=True)
            sorted_v = sorted(sorted_v, key=config.compare_key_3)

            pre_end = -1
            count = 1
            TrueFlag = 0
            
            for ele in sorted_v:
                if ele.count(';')>0:
                    continue
                    
                ele_start = int(ele.split(',')[0])
                ele_end = int(ele.split(',')[-1])
                if (pre_end + 1) == ele_start:
                    count += 1
                if ele in cmp_true:
                    TrueFlag = 1
                else:
                    TrueFlag = 0
                if count >= 3 and TrueFlag == 1:
                    if len(bytes(payload_message[ele_start: ele_end+1]))>1:
                        continue
                    if hex(ord(bytes(payload_message[ele_start: ele_end+1])))== key:
                        Polyglot_separator.append(ele)
                pre_end = ele_end
            
    
    print(f"Polyglot_Separator:{Polyglot_separator}")
    write_to_file(f"Polyglot_Separator:{Polyglot_separator}")

    return Polyglot_separator


def Length_Infer(payload_message, threadId, lengthlog, addsub, addop, cmpjmp, loops, taint_func, taintlog):
    Polyglot_length = set()
    Polyglot_variables = set()
    write_to_file("")
    method_5 = []
    taintaddrs = []
    item_start = 0
    for start,end in taintlog:
        addr_i = start
        item_start = addr_i
        for i in range(end-start):
            taintaddrs.append(addr_i+i)

    for length in lengthlog:
        write_to_file("Length:\t{}".format(length))
    hashmap = {}
    
    for item,item2 in addsub:
        if item not in hashmap:
            hashmap[item] = 0
        hashmap[item] = hashmap[item]+1

    for item,item2 in addop:
        nums = item2.split(';')
        item = item.strip(';')
        items = item.split(',')
        for num in nums:
            if(int(num,16) in taintaddrs):
                item_start1 = int(num,16) - item_start
                method_5.append((item, item_start1))
        
                
    
    length_results_3 = set()

    for instruction1, instruction2 in cmpjmp:
        content_1 = instruction1.strip().split('\t')
        content_2 = instruction2.strip().split('\t')
        thread = int(content_1[1])
        if thread != threadId: continue
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
                length_results_3.add(content_1[2])       
    for item in length_results_3:
        write_to_file("\t{}".format(item))
        Polyglot_length.add(item.strip(';'))

    if not taint_func:
        write_to_file("\tNone")
    else:
        for item in taint_func:
            write_to_file(item)
    if not method_5:
        write_to_file("\tNone")
    for off,add in method_5:
        write_to_file("\t{}: {}".format(off,add))
        Polyglot_length.add(off)
        if int(add) > int(off.split(',')[0]):
            v_start = int(add)
            if off.count(';') >0:
                off = off.split(';')[0]
            size = int.from_bytes(payload_message[int(off.split(',')[0]):int(off.split(',')[-1])+1], byteorder=config.endian)

            if size == 0:
                continue
            v_end = v_start + size
            variables = ','.join(str(i) for i in range(v_start, v_end))
            print(f"variables:{variables}")
            Polyglot_variables.add(variables)

    
    return list(Polyglot_length), list(Polyglot_variables)


def Analysis_cmp(payload_message, protocol_type, hashmap1, hashmap2, cmp_true):
    if not hashmap1:
        return None, None
    write_to_file("")
    write_to_file("field-to-constantcmp")
    for key in list(hashmap1.keys()):
        if key.count(';')>0:
            write_to_file("\tcompare_Between_Taints:{}".format(key))
            write_to_file("\t\tvalue: {}".format(hashmap1[key]))
        else:
            write_to_file("\t{}:{}".format(key, hashmap1[key]))
    
    write_to_file(" ")
    write_to_file("constantcmp-to-field")
    for key in list(hashmap2.keys()):
        hashmap2[key]=sorted(hashmap2[key])
        write_to_file("\t{}:{}".format(key, hashmap2[key]))
    write_to_file(" ")

    write_to_file("cmp_true")
    for ele in cmp_true:
        write_to_file(ele)

    Polyglot_separator = Seperator_Infer(payload_message, hashmap2, cmp_true)
    Polyglot_keyword = Keywords_Infer(protocol_type, hashmap1, cmp_true, Polyglot_separator)
    
    return Polyglot_keyword, Polyglot_separator


def BaselineAnalysis(payload_message, result_dir_input, thread, protocol_type, hashmap1, hashmap2, sizeofTaint, cmp_true, lengthlog, addsub, addop, loops, cmpjmp, taint_func, taintlog):
    global semantic_result_dir
    semantic_result_dir = result_dir_input
    
    with open(semantic_result_dir + "loops.txt", "r") as l:
        loopsinfo = l.readlines()
    
    if sizeofTaint==0:
        return
    write_to_file("===============SEMANTIC===================")
    write_to_file("sizeofTaint: {}".format(sizeofTaint))

    Polyglot_keyword, Polyglot_separator = Analysis_cmp(payload_message, protocol_type, hashmap1, hashmap2, cmp_true)
    print("fff")
    Polyglot_length, Polyglot_variables = Length_Infer(payload_message, thread,lengthlog, addsub, addop, cmpjmp, loops, taint_func, taintlog)

    return Polyglot_length,Polyglot_keyword, Polyglot_separator, Polyglot_variables
 