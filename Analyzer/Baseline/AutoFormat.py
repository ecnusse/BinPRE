from collections import deque

import config
import matplotlib
import matplotlib.pyplot as plt


class Node:
    def __init__(self, offset_interval):
        self.offset_interval = offset_interval
        self.children = []


def write_to_file_tree(result_dir, data):
    with open(result_dir + 'tree.txt', 'a', encoding='utf-8') as t:
        t.write(data + '\n')
    t.close()

def visualize_tree(root, filename):
    fig, ax = plt.subplots(figsize=(26, 26))
    fig, ax = plt.subplots(figsize=(36, 36))

    def plot_node(node, x, y):
        ax.annotate(str(node.offset_interval), xy=(x, y), ha="center", va="center",
                    bbox=dict(boxstyle="round", fc="w"), fontsize=14)

        num_children = len(node.children)
        if num_children > 0:
            x_min = x - num_children / 2.0
            for i, child in enumerate(node.children):
                x_offset = i + 0.5
                plot_node(child, x_min + x_offset, y - 1)

                ax.plot([x, x_min + x_offset], [y, y - 1], 'k-', linewidth=0.5)

    plot_node(root, 0, 0)
    ax.set_aspect('equal')
    ax.axis('off')
    plt.savefig(filename)


def print_fftree(result_dir, node):  
    queue = deque()
    depth = 0

    queue.append((node, depth))

    while queue:
        node, depth = queue.popleft()

        write_to_file_tree(result_dir, str(node.offset_interval))
        write_to_file_tree(result_dir, "depth" + " " + str(depth))

        for child in node.children:
            queue.append((child, depth + 1))

def merge_duplicates(node):
    if len(node.children) == 0:
        return
    if len(node.children) == 1:
        child = node.children[0]

        if child.offset_interval == node.offset_interval:
            node.children = child.children
            merge_duplicates(node)
        else:
            merge_duplicates(child)
    else:
        for child in node.children:
            merge_duplicates(child)

def findInChild(node, i):
    for child in node.children:
        start = list(child.offset_interval)[0]
        end = list(child.offset_interval)[-1]
        if start <= i and end >= i:
            return 1
        if start > i:
            break
    return 0

def add_missing(node):
    if len(node.children) == 0:
        return

    for i in range(node.offset_interval[0], node.offset_interval[-1] + 1):
        flag = findInChild(node, i)
        if flag == 0:
            node.children.append(Node([i]))
    sort_tree(node)
    for child in node.children:
        add_missing(child)

def sort_tree(node):
    if len(node.children) == 0:
        return
    children_list = sorted(list(node.children), key=lambda x: list(x.offset_interval)[0])
    node.children = children_list
    for child in node.children:
        sort_tree(child)


def optimize_tree(result_dir, ftree):
    
    merge_duplicates(ftree)
    add_missing(ftree)
    print_fftree(result_dir, ftree)

def FormatPrint_AutoFormat(sizeofTaint, inst_list, loops, offset_instlog, result_dir):
    if not offset_instlog:
        return
   
    ROOT = Node(list(range(sizeofTaint)))
    ftree = ROOT

    log = inst_list
    p = set([log[0].offset])
    for i in range(1, len(log)):

        q = set([log[i].offset])
        if int(log[i].offset) >= sizeofTaint or int(log[i].offset) < 0:
            q = set([log[i].offset])
            continue

        if (((int(log[i].offset) == int(log[i - 1].offset) + 1) or (
                int(log[i].offset) == int(log[i - 1].offset))) and (
                log[i].stack == log[i - 1].stack)):  

            p |= q

        else:
            v = Node(p)  
            u = ftree
            v_list = sorted(v.offset_interval)
            v_start = v_list[0]
            v_end = v_list[-1]
            while True:

                for child in u.children:
                    child_list = sorted(child.offset_interval)
                    child_start = child_list[0]
                    child_end = child_list[-1]
                    if child_start <= v_start and child_end >= v_end:
                        u = child
                        if child_start == v_start and child_end == v_end:
                            flag = 1
                        break
                else:
                    break
            if 1:  
                for child in u.children:
                    child_list = sorted(child.offset_interval)
                    child_start = child_list[0]
                    child_end = child_list[-1]
                    if child_start >= v_start and child_end <= v_end:
                        if not (child_start == v_start and child_end == v_end):
                            v.children.append(child)
                u.children = [child for child in u.children if child not in v.children]
                v.offset_interval = sorted(v.offset_interval)
                u.children.append(v)
            p = q
    sort_tree(ftree)
    optimize_tree(result_dir, ftree)

    return ftree

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

    # [INFO Extractor]
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



def Processing_autoformatTree(AutoFormat_ftree):

    leaf_nodes = []
    ftree = AutoFormat_ftree
    def traverse(node):
        if not node.children:  
            leaf_nodes.append(node)
        else:
            for child in node.children:
                traverse(child)

    traverse(ftree)  

    Syntax_AutoFormat = set()

    for node in leaf_nodes:
        offset_interval = node.offset_interval
        boundary1 = int(offset_interval[0])-1
        boundary2 = int(offset_interval[-1])
        Syntax_AutoFormat.add(boundary1)
        Syntax_AutoFormat.add(boundary2)
    
    return Syntax_AutoFormat

def convert_list(input_list):
    result = []
    prev_num = -1
    
    for i in range(1,len(input_list)):
        pre_index = input_list[i-1] + 1
        post_index = input_list[i]
        if pre_index == post_index:
            result.append(str(pre_index))
        else:
            curr = ''
            curr += str(pre_index)
            for j in range(pre_index+1, post_index+1):
                curr += ','
                curr += str(j)

            result.append(curr)
    
    return result
