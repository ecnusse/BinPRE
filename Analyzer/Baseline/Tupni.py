import config

def greedy_GetMaxWeight(chunks):
    sorted_blocks = sorted(chunks, key=lambda x: x[1], reverse=True)
    id_set = set()
    S = []
    for block in sorted_blocks:
        if id_set.isdisjoint(set(block[0].split(','))):
            id_set |= set(block[0].split(','))
            S.append(block)

    return S


def FormatPrint_Tupni(sizeofTaint, inst_list, inst_field, loops, result_dir):
    # --flat
    chunks = []
    loop_field_log = set()
    Tupni_format = []
    for i in range(sizeofTaint):
        chunks.append((str(i), 0))
    for inst in inst_field:
        curr_taint = inst.field
        for i, (k, v) in enumerate(chunks):
            if curr_taint == k:
                chunks[i] = (k, v + 1)
                break
        else:
            chunks.append((curr_taint, 1))

    chunks = sorted(chunks, key=lambda x: config.compare_key_1(x[0]), reverse=True)
    chunks = sorted(chunks, key=config.compare_key_2)

    S = greedy_GetMaxWeight(chunks)
    S = sorted(S, key=config.compare_key_2)

    config.write_to_file(result_dir, " ")
    config.write_to_file(result_dir, "Format_[FLAT: Tupni]")

    # --structured
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
    config.write_to_file(result_dir, " ")
    config.write_to_file(result_dir, "Format_[Structured: Tupni]")
    for k, Q in list(r.items()):  
        if k == "0": continue
        Q_insts = {}
        for Qi in Q:  
            addrs = []
            for inst in Qi:
                addrs.append(inst.address)
            Q_insts.setdefault(tuple(addrs), set()).add(tuple(Qi))
        for addrs, Qis in list(Q_insts.items()):
            Tupni_Structured = []
            if len(Qis) > 1:
                for Qi in Qis:
                    offsets = []
                    for inst in Qi:
                        offsets.append(inst.offset)
                    Tupni_Structured.append(offsets)
            else:
                offsets = set()
                for inst in list(Qis)[0]:
                    offsets.add(inst.offset)
                Tupni_Structured.append(offsets)
            curr_results = set()
            for eles in Tupni_Structured:
                for ele in eles:
                    curr_results.add(ele)
            record = ""
            for item in curr_results:
                record += str(item) + ","
            config.write_to_file(result_dir, "\t" + record)
            loop_field_log.add(record)
    
    loop_record = set()
    for loop_field in loop_field_log:
        byte = loop_field.strip(',').split(',')
        byte = sorted(byte, key=config.compare_key_3)
        byte_s = [byte[0]]
        for byte_i in range(1, len(byte)):
            if int(byte[byte_i]) == int(byte[byte_i-1])+1:
                byte_s.append(byte[byte_i])
            else:
                field_chunk = ','.join(str(j) for j in byte_s)
                if field_chunk != '':
                    loop_record.add(field_chunk)
                byte_s = []
        field_chunk = ','.join(str(j) for j in byte_s)
        if field_chunk != '':
            loop_record.add(field_chunk)

    flag_field = set()
    for k, v in S:
        k_start = int(k.split(',')[0])
        k_end = int(k.split(',')[-1])
        flag_field.add(k)
        loop_record.add(k)
    
    loop_record = sorted(loop_record, key=lambda x: config.compare_key_1(x[0]), reverse=True)
    loop_record = sorted(loop_record, key=config.compare_key_3)

    merged_list = []

    for item in loop_record:
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

    
    
    Tupni_format = merged_list

    
    Tupni_format = sorted(Tupni_format, key=lambda x: config.compare_key_1(x[0]), reverse=True)
    Tupni_format = sorted(Tupni_format, key=config.compare_key_3)
    
    flag_field = sorted(list(flag_field), key=lambda x: config.compare_key_1(x[0]), reverse=True)
    flag_field = sorted(flag_field, key=config.compare_key_3)


    print("****************Tupni********************")
    print(f"Tupni_length: ")
    print(f"Tupni_checksum: ")
    print(f"==Flat Field: {flag_field}")
    print(f"Tupni_format: {Tupni_format}")
    

    return Tupni_format

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

