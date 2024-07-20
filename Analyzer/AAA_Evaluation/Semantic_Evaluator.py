import sys
sys.path.append('/home/linuxbrew/pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/BinPRE/Analyzer/config')
import config

Semantic_Groundtruth = config.Semantic_Groundtruth
Semantic_Functions_Groundtruth = config.Semantic_Functions_Groundtruth

def metrix_Cal(msg_semanticTruth,msg_Res, msg_fields, msg_len):
    '''
    pre = correct_format_inferred_correct_semantic/correct_format_inferred_semantic
    rec = correct_format_inferred_correct_semantic/correct_format
    '''
    correct_format_inferred_semantic = 0
    correct_format_inferred_correct_semantic = 0

    for k,v in msg_Res.items():
        if k in msg_semanticTruth:
            correct_format_inferred_semantic += len(v)
            if msg_semanticTruth[k] in v:
                correct_format_inferred_correct_semantic += 1

    correct_format = 0
    for field in msg_fields:
        if field in msg_semanticTruth:
            correct_format += 1

    print(f"correct_format_inferred_correct_semantic:{correct_format_inferred_correct_semantic}")
    print(f"\ncorrect_format_inferred_semantic:{correct_format_inferred_semantic}")
    print(f"correct_format:{correct_format}")
    semantic_pre = correct_format_inferred_correct_semantic/correct_format_inferred_semantic
    semantic_rec = correct_format_inferred_correct_semantic/correct_format


    return semantic_pre, semantic_rec

def metrix_Cal_Func(msg_semanticTruth, msg_Res, msg_fields, msg_len, msg_fieldTruth):
    '''
    pre = correct_format_inferred_correct_semantic/correct_format_inferred_semantic
    rec = correct_format_inferred_correct_semantic/correct_format
    '''
    correct_format_inferred_semantic = 0
    correct_format_inferred_correct_semantic = 0

    for k,v in msg_Res.items():
        if k in msg_fieldTruth:
            correct_format_inferred_semantic += len(v)

    for k,v in msg_Res.items():
        if k in msg_semanticTruth:
            if msg_semanticTruth[k] in v:
                correct_format_inferred_correct_semantic += 1

    correct_format = 0
    for field in msg_fields:
        if field in msg_semanticTruth:
            correct_format += 1

    print(f"correct_format_inferred_correct_semantic:{correct_format_inferred_correct_semantic}")
    print(f"\ncorrect_format_inferred_semantic:{correct_format_inferred_semantic}")
    print(f"correct_format:{correct_format}")
    semantic_pre = correct_format_inferred_correct_semantic/correct_format_inferred_semantic
    if correct_format == 0:
        semantic_rec = 0
    else:
        semantic_rec = correct_format_inferred_correct_semantic/correct_format


    return semantic_pre, semantic_rec


def Processing(Static_Res_i):
    msg_syntax = Static_Res_i.syntax
    msg_semantic = Static_Res_i.semantic

    msg_semanticRes = {}

    for i in range(0,len(msg_syntax)):
        msg_semanticRes[msg_syntax[i]] = msg_semantic[i]
    
    return msg_semanticRes

def BinPRE_Semantic_Types_Evaluator(payload_message, Pre_message_Result, message_Result, commandOffset):
    print("\n\n\nSemantic-Types Evaluation Part For BinPRE(no validation)---------------------------------")
    
    '''Semantic-Type'''
    semantic_usedPre,msg_Pre, msg_Rec =0,0,0

    # msg_semanticTruth
    True_static_groudtruth = 0
    static_groudtruth = set()
    True_bytes_groudtruth = 0
    bytes_groudtruth = set()
    True_string_groudtruth = 0
    string_groudtruth = set()
    True_integer_groudtruth = 0
    integer_groudtruth = set()
    True_group_groudtruth = 0
    group_groudtruth = set()

    Inferred_True_static = 0
    Inferred_True_bytes = 0
    Inferred_True_string = 0
    Inferred_True_integer = 0
    Inferred_True_group = 0
    
    Inferred_static = 0
    Inferred_bytes = 0
    Inferred_string = 0
    Inferred_integer = 0
    Inferred_group = 0


    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]

        if config.evaluation_mode == 'index':
            msg_semanticTruth = Semantic_Groundtruth[i]
        else:
            msg_semanticTruth = Semantic_Groundtruth[msg_command]

        msg_semanticRes = Pre_message_Result[i].field_types


        print(f"Msg {i} semantic evaluation:***\n")
        print(f"msg_semanticTruth:{msg_semanticTruth}")
        print(f"msg_semanticRes:{msg_semanticRes}\n")

        msg_pre, msg_rec= metrix_Cal(msg_semanticTruth,msg_semanticRes, Pre_message_Result[i].fields, msg_len)
        print(f"msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        
        msg_Pre += msg_pre
        msg_Rec += msg_rec
    
        for f,r in msg_semanticTruth.items():
            if (config.semantic_Types[0] in msg_semanticTruth[f]):
                True_static_groudtruth += 1
                static_groudtruth.add(f)

            if (config.semantic_Types[4] in msg_semanticTruth[f]):
                True_bytes_groudtruth += 1
                bytes_groudtruth.add(f)
            
            if (config.semantic_Types[2] in msg_semanticTruth[f]):
                True_string_groudtruth += 1
                string_groudtruth.add(f)
            
            if (config.semantic_Types[3] in msg_semanticTruth[f]):
                True_integer_groudtruth += 1
                integer_groudtruth.add(f)
            
            if (config.semantic_Types[1] in msg_semanticTruth[f]):
                True_group_groudtruth += 1
                group_groudtruth.add(f)

        for f,r in msg_semanticRes.items():

            if config.semantic_Types[0] in r:
                Inferred_static += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[0] in msg_semanticTruth[f]):
                    Inferred_True_static += 1
            if config.semantic_Types[4] in r:
                Inferred_bytes += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[4] in msg_semanticTruth[f]):
                    Inferred_True_bytes += 1
            
            if config.semantic_Types[2] in r:
                Inferred_string += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[2] in msg_semanticTruth[f]):
                    Inferred_True_string += 1
            if config.semantic_Types[3] in r:
                Inferred_integer += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[3] in msg_semanticTruth[f]):
                    Inferred_True_integer += 1
            if config.semantic_Types[1] in r:
                Inferred_group += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[1] in msg_semanticTruth[f]):
                    Inferred_True_group += 1

    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    if (Average_Pre + Average_Rec) > 0:
        F1_score = (2 * Average_Pre * Average_Rec) / (Average_Pre + Average_Rec)
    else:
        F1_score = 0
    

    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1_score:{F1_score}")

    if Inferred_static > 0:
        static_Pre = Inferred_True_static / Inferred_static
    else:
        static_Pre = 0
    if True_static_groudtruth >0:
        static_Rec = Inferred_True_static / True_static_groudtruth
    else:
        static_Rec = 0
    if (static_Pre + static_Rec) > 0:
        static_F1 = (2 * static_Pre * static_Rec) / (static_Pre + static_Rec)
    else:
        static_F1 = 0
    '''bytes'''
    if Inferred_bytes == 0:
        bytes_Pre = 0
    else:
        bytes_Pre = Inferred_True_bytes / Inferred_bytes
    
    if True_bytes_groudtruth == 0:
        bytes_Rec = 0
    else:
        bytes_Rec = Inferred_True_bytes / True_bytes_groudtruth
    
    if (bytes_Pre + bytes_Rec) > 0:
        bytes_F1 = (2 * bytes_Pre * bytes_Rec) / (bytes_Pre + bytes_Rec)
    else:
        bytes_F1 = 0
    '''string'''
    if Inferred_string == 0:
        string_Pre = 0
    else:
        string_Pre = Inferred_True_string / Inferred_string
    
    if True_string_groudtruth == 0:
        string_Rec = 0
    else:
        string_Rec = Inferred_True_string / True_string_groudtruth
    
    if (string_Pre + string_Rec) > 0:
        string_F1 = (2 * string_Pre * string_Rec) / (string_Pre + string_Rec)
    else:
        string_F1 = 0
    '''integer'''
    if Inferred_integer == 0:
        integer_Pre = 0
    else:
        integer_Pre = Inferred_True_integer / Inferred_integer
    
    if True_integer_groudtruth == 0:
        integer_Rec = 0
    else:
        integer_Rec = Inferred_True_integer / True_integer_groudtruth
    
    if (integer_Pre + integer_Rec) > 0:
        integer_F1 = (2 * integer_Pre * integer_Rec) / (integer_Pre + integer_Rec)
    else:
        integer_F1 = 0

    '''group'''
    if Inferred_group == 0:
        group_Pre = 0
    else:
        group_Pre = Inferred_True_group / Inferred_group
    
    if True_group_groudtruth == 0:
        group_Rec = 0
    else:
        group_Rec = Inferred_True_group / True_group_groudtruth
    
    if (group_Pre + group_Rec) > 0:
        group_F1 = (2 * group_Pre * group_Rec) / (group_Pre + group_Rec)
    else:
        group_F1 = 0

    no_Average_Pre = Average_Pre
    no_Average_Rec = Average_Rec
    no_F1_score = F1_score

    with open(config.Evaluation_Res, "a") as file:
        file.write("\n\n\Semantic-Type Evaluation Part For BinPRE(no validation)---------------------------------\n")
        file.write(f"no_Average_Pre:{Average_Pre}\n")
        file.write(f"no_Average_Rec:{Average_Rec}\n")
        file.write(f"no_F1_score:{F1_score}\n")

        file.write(f"\nno_static_Pre:{static_Pre}\n")
        file.write(f"no_static_Rec:{static_Rec}\n")
        file.write(f"no_static_F1:{static_F1}\n")
        file.write(f"no_static_groudtruth:{static_groudtruth}\n")

        file.write(f"\nno_integer_Pre:{integer_Pre}\n")
        file.write(f"no_integer_Rec:{integer_Rec}\n")
        file.write(f"no_integer_F1:{integer_F1}\n")
        file.write(f"no_integer_groudtruth:{integer_groudtruth}\n") 

        file.write(f"\nno_group_Pre:{group_Pre}\n")
        file.write(f"no_group_Rec:{group_Rec}\n")
        file.write(f"no_group_F1:{group_F1}\n")
        file.write(f"no_group_groudtruth:{group_groudtruth}\n") 

        file.write(f"\nno_bytes_Pre:{bytes_Pre}\n")
        file.write(f"no_bytes_Rec:{bytes_Rec}\n")
        file.write(f"no_bytes_F1:{bytes_F1}\n")
        file.write(f"no_bytes_groudtruth:{bytes_groudtruth}\n") 

        file.write(f"\nno_string_Pre:{string_Pre}\n")
        file.write(f"no_string_Rec:{string_Rec}\n")
        file.write(f"no_string_F1:{string_F1}\n")
        file.write(f"no_string_groudtruth:{string_groudtruth}\n") 


         

    print("\n\n\nSemantic-Types Evaluation Part For BinPRE(Validated)---------------------------------")
    

    '''Semantic-Type'''
    semantic_usedPre,msg_Pre, msg_Rec =0,0,0

    # msg_semanticTruth
    True_static_groudtruth = 0
    static_groudtruth = set()
    True_bytes_groudtruth = 0
    bytes_groudtruth = set()
    True_string_groudtruth = 0
    string_groudtruth = set()
    True_integer_groudtruth = 0
    integer_groudtruth = set()
    True_group_groudtruth = 0
    group_groudtruth = set()

    Inferred_True_static = 0
    Inferred_True_bytes = 0
    Inferred_True_string = 0
    Inferred_True_integer = 0
    Inferred_True_group = 0
    
    Inferred_static = 0
    Inferred_bytes = 0
    Inferred_string = 0
    Inferred_integer = 0
    Inferred_group = 0

    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]

        if config.evaluation_mode == 'index':
            msg_semanticTruth = Semantic_Groundtruth[i]
        else:
            msg_semanticTruth = Semantic_Groundtruth[msg_command]


        msg_semanticRes = message_Result[i].field_types


        print(f"Msg {i} semantic evaluation:***\n")
        print(f"msg_semanticTruth:{msg_semanticTruth}")
        print(f"msg_semanticRes:{msg_semanticRes}\n")

        msg_pre, msg_rec= metrix_Cal(msg_semanticTruth,msg_semanticRes, message_Result[i].fields, msg_len)
        print(f"msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        
        msg_Pre += msg_pre
        msg_Rec += msg_rec



        for f,r in msg_semanticTruth.items():
            if (config.semantic_Types[0] in msg_semanticTruth[f]):
                True_static_groudtruth += 1
                static_groudtruth.add(f)

            if (config.semantic_Types[4] in msg_semanticTruth[f]):
                True_bytes_groudtruth += 1
                bytes_groudtruth.add(f)
            
            if (config.semantic_Types[2] in msg_semanticTruth[f]):
                True_string_groudtruth += 1
                string_groudtruth.add(f)
            
            if (config.semantic_Types[3] in msg_semanticTruth[f]):
                True_integer_groudtruth += 1
                integer_groudtruth.add(f)
            
            if (config.semantic_Types[1] in msg_semanticTruth[f]):
                True_group_groudtruth += 1
                group_groudtruth.add(f)

        for f,r in msg_semanticRes.items():

            if config.semantic_Types[0] in r:
                Inferred_static += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[0] in msg_semanticTruth[f]):
                    Inferred_True_static += 1
            if config.semantic_Types[4] in r:
                Inferred_bytes += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[4] in msg_semanticTruth[f]):
                    Inferred_True_bytes += 1
            
            if config.semantic_Types[2] in r:
                Inferred_string += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[2] in msg_semanticTruth[f]):
                    Inferred_True_string += 1
            if config.semantic_Types[3] in r:
                Inferred_integer += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[3] in msg_semanticTruth[f]):
                    Inferred_True_integer += 1
            if config.semantic_Types[1] in r:
                Inferred_group += 1
                if (f in msg_semanticTruth) and (config.semantic_Types[1] in msg_semanticTruth[f]):
                    Inferred_True_group += 1
        

    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    if (Average_Pre + Average_Rec) > 0:
        F1_score = (2 * Average_Pre * Average_Rec) / (Average_Pre + Average_Rec)
    else:
        F1_score = 0
    if Inferred_static >0:
        static_Pre = Inferred_True_static / Inferred_static
    else:
        static_Pre = 0
    
    if (static_Pre + static_Rec) > 0:
        static_F1 = (2 * static_Pre * static_Rec) / (static_Pre + static_Rec)
    else:
        static_F1 = 0
    '''bytes'''
    if Inferred_bytes == 0:
        bytes_Pre = 0
    else:
        bytes_Pre = Inferred_True_bytes / Inferred_bytes
    
    if True_bytes_groudtruth == 0:
        bytes_Rec = 0
    else:
        bytes_Rec = Inferred_True_bytes / True_bytes_groudtruth
    
    if (bytes_Pre + bytes_Rec) > 0:
        bytes_F1 = (2 * bytes_Pre * bytes_Rec) / (bytes_Pre + bytes_Rec)
    else:
        bytes_F1 = 0
    '''string'''
    if Inferred_string == 0:
        string_Pre = 0
    else:
        string_Pre = Inferred_True_string / Inferred_string
    
    if True_string_groudtruth == 0:
        string_Rec = 0
    else:
        string_Rec = Inferred_True_string / True_string_groudtruth
    
    if (string_Pre + string_Rec) > 0:
        string_F1 = (2 * string_Pre * string_Rec) / (string_Pre + string_Rec)
    else:
        string_F1 = 0
    '''integer'''
    if Inferred_integer == 0:
        integer_Pre = 0
    else:
        integer_Pre = Inferred_True_integer / Inferred_integer
    
    if True_integer_groudtruth == 0:
        integer_Rec = 0
    else:
        integer_Rec = Inferred_True_integer / True_integer_groudtruth
    
    if (integer_Pre + integer_Rec) > 0:
        integer_F1 = (2 * integer_Pre * integer_Rec) / (integer_Pre + integer_Rec)
    else:
        integer_F1 = 0

    '''group'''
    if Inferred_group == 0:
        group_Pre = 0
    else:
        group_Pre = Inferred_True_group / Inferred_group
    
    if True_group_groudtruth == 0:
        group_Rec = 0
    else:
        group_Rec = Inferred_True_group / True_group_groudtruth
    
    if (group_Pre + group_Rec) > 0:
        group_F1 = (2 * group_Pre * group_Rec) / (group_Pre + group_Rec)
    else:
        group_F1 = 0

    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1_score:{F1_score}")
    

    


    with open(config.Evaluation_Res, "a") as file:
        file.write("\n\n\Semantic-Type Evaluation Part For BinPRE(Validated)---------------------------------\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n")

        file.write(f"\nstatic_Pre:{static_Pre}\n")
        file.write(f"static_Rec:{static_Rec}\n")
        file.write(f"static_F1:{static_F1}\n")
        file.write(f"static_groudtruth:{static_groudtruth}\n")

        file.write(f"\ninteger_Pre:{integer_Pre}\n")
        file.write(f"integer_Rec:{integer_Rec}\n")
        file.write(f"integer_F1:{integer_F1}\n")
        file.write(f"integer_groudtruth:{integer_groudtruth}\n") 

        file.write(f"\ngroup_Pre:{group_Pre}\n")
        file.write(f"group_Rec:{group_Rec}\n")
        file.write(f"group_F1:{group_F1}\n")
        file.write(f"group_groudtruth:{group_groudtruth}\n")    

        file.write(f"\nbytes_Pre:{bytes_Pre}\n")
        file.write(f"bytes_Rec:{bytes_Rec}\n")
        file.write(f"bytes_F1:{bytes_F1}\n")
        file.write(f"bytes_groudtruth:{bytes_groudtruth}\n") 

        file.write(f"\nstring_Pre:{string_Pre}\n")
        file.write(f"string_Rec:{string_Rec}\n")
        file.write(f"string_F1:{string_F1}\n")
        file.write(f"string_groudtruth:{string_groudtruth}\n") 
    
    return no_Average_Pre, no_Average_Rec, no_F1_score, Average_Pre, Average_Rec, F1_score

            

def BinPRE_Semantic_Functions_Evaluator(payload_message, Pre_message_Result, message_Result, commandOffset):
    print("\n\n\nSemantic-Functions Evaluation Part For BinPRE(no validation)---------------------------------")
    
    '''Semantic-Function'''
    semantic_usedPre,msg_Pre, msg_Rec =0,0,0

    no_BinPRE_command_count = 0
    no_BinPRE_command_correct = 0

    BinPRE_length_correct = 0
    BinPRE_command_correct = 0
    BinPRE_length_count = 0
    BinPRE_command_count = 0

    True_delim_groudtruth = 0
    Inferred_delim = 0
    Inferred_True_delim = 0
    delim_groudtruth = set()

    True_aligned_groudtruth = 0
    Inferred_aligned = 0
    Inferred_True_aligned = 0
    aligned_groudtruth = set()

    True_filename_groudtruth = 0
    Inferred_filename = 0
    Inferred_True_filename = 0
    filename_groudtruth = set()

    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]

        if config.evaluation_mode == 'index':
            msg_semanticTruth = Semantic_Functions_Groundtruth[i]
            msg_fieldTruth = Semantic_Groundtruth[i]
        else:
            msg_semanticTruth = Semantic_Functions_Groundtruth[msg_command]
            msg_fieldTruth = Semantic_Groundtruth[msg_command]

        msg_semanticRes = Pre_message_Result[i].field_funcs

        for f,r in msg_semanticRes.items():
            if config.semantic_Functions[0] in r:
                no_BinPRE_command_count += 1
                if f == config.commandOffset:
                    no_BinPRE_command_correct += 1


        print(f"Msg {i} semantic evaluation:***\n")
        print(f"msg_semanticTruth:{msg_semanticTruth}")
        print(f"msg_semanticRes:{msg_semanticRes}\n")

        msg_pre, msg_rec= metrix_Cal_Func(msg_semanticTruth,msg_semanticRes, Pre_message_Result[i].fields, msg_len, msg_fieldTruth)
        print(f"msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        
        msg_Pre += msg_pre
        msg_Rec += msg_rec
        for f,r in msg_semanticRes.items():
            print(f"f:{f}, r:{r}")
            if config.semantic_Functions[0] in r:
                BinPRE_command_count += 1
                if f == config.commandOffset:
                    BinPRE_command_correct += 1
            if config.semantic_Functions[1] in r:
                BinPRE_length_count += 1
                if f == config.lengthOffset:
                    BinPRE_length_correct += 1
        
        
        
        for f,r in msg_semanticTruth.items():
            if (config.semantic_Functions[2] in msg_semanticTruth[f]):
                True_delim_groudtruth += 1
                delim_groudtruth.add(f)
            if (config.semantic_Functions[4] in msg_semanticTruth[f]):
                True_aligned_groudtruth += 1
                aligned_groudtruth.add(f)
            if (config.semantic_Functions[5] in msg_semanticTruth[f]):
                True_filename_groudtruth += 1
                filename_groudtruth.add(f)


        for f,r in msg_semanticRes.items():

            if config.semantic_Functions[2] in r:
                Inferred_delim += 1
                if (f in msg_semanticTruth) and (config.semantic_Functions[2] in msg_semanticTruth[f]):
                    Inferred_True_delim += 1
            
            if config.semantic_Functions[4] in r:
                Inferred_aligned += 1
                if (f in msg_semanticTruth) and (config.semantic_Functions[4] in msg_semanticTruth[f]):
                    Inferred_True_aligned += 1
            
            if config.semantic_Functions[5] in r:
                Inferred_filename += 1
                if (f in msg_semanticTruth) and (config.semantic_Functions[5] in msg_semanticTruth[f]):
                    Inferred_True_filename += 1

    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    if (Average_Pre + Average_Rec) > 0:
        F1_score = (2 * Average_Pre * Average_Rec) / (Average_Pre + Average_Rec)
    else:
        F1_score = 0
    

    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1_score:{F1_score}")

    no_BinPRE_Command_rec = no_BinPRE_command_correct/len(payload_message)
    if no_BinPRE_command_count>0:
        no_BinPRE_Command_pre = no_BinPRE_command_correct / no_BinPRE_command_count
        if (no_BinPRE_Command_pre + no_BinPRE_Command_rec) > 0:
            no_BinPRE_Command_F1 = (2 * no_BinPRE_Command_pre * no_BinPRE_Command_rec) / (no_BinPRE_Command_pre + no_BinPRE_Command_rec)
        else:
            no_BinPRE_Command_F1 = 0
    else:
        no_BinPRE_Command_pre = 0
        no_BinPRE_Command_F1 = 0
    
    BinPRE_Command_rec = BinPRE_command_correct/len(payload_message)
    BinPRE_Length_rec = BinPRE_length_correct/len(payload_message)
    if BinPRE_command_count>0:
        BinPRE_Command_pre = BinPRE_command_correct/BinPRE_command_count
        if (BinPRE_Command_pre + BinPRE_Command_rec) > 0:
            BinPRE_Command_F1 = (2 * BinPRE_Command_pre * BinPRE_Command_rec) / (BinPRE_Command_pre + BinPRE_Command_rec) 
        else:
            BinPRE_Command_F1 = 0
    else:
        BinPRE_Command_pre = 0
        BinPRE_Command_F1 = 0
    if BinPRE_length_count>0:
        BinPRE_Length_pre = BinPRE_length_correct / BinPRE_length_count
        if (BinPRE_Length_pre + BinPRE_Length_rec) > 0:
            BinPRE_Length_F1 = (2 * BinPRE_Length_pre * BinPRE_Length_rec) / (BinPRE_Length_pre + BinPRE_Length_rec)
        else:
            BinPRE_Length_F1 = 0
    else:
        BinPRE_Length_pre = 0
        BinPRE_Length_F1 = 0
    if True_delim_groudtruth > 0:
        BinPRE_Delim_rec = Inferred_True_delim/True_delim_groudtruth
    else:
        BinPRE_Delim_rec = 0
    
    if Inferred_delim > 0:
        BinPRE_Delim_pre = Inferred_True_delim/Inferred_delim
    else:
        BinPRE_Delim_pre = 0
    
    if (BinPRE_Delim_rec + BinPRE_Delim_pre) > 0:
        BinPRE_Delim_F1 = (2 * BinPRE_Delim_rec * BinPRE_Delim_pre) / (BinPRE_Delim_rec + BinPRE_Delim_pre)
    else:
        BinPRE_Delim_F1 = 0
    if True_aligned_groudtruth > 0:
        BinPRE_aligned_rec = Inferred_True_aligned/True_aligned_groudtruth
    else:
        BinPRE_aligned_rec = 0
    
    if Inferred_aligned > 0:
        BinPRE_aligned_pre = Inferred_True_aligned/Inferred_aligned
    else:
        BinPRE_aligned_pre = 0
    
    if (BinPRE_aligned_rec + BinPRE_aligned_pre) > 0:
        BinPRE_aligned_F1 = (2 * BinPRE_aligned_rec * BinPRE_aligned_pre) / (BinPRE_aligned_rec + BinPRE_aligned_pre)
    else:
        BinPRE_aligned_F1 = 0
    if True_filename_groudtruth > 0:
        BinPRE_filename_rec = Inferred_True_filename/True_filename_groudtruth
    else:
        BinPRE_filename_rec = 0
    
    if Inferred_filename > 0:
        BinPRE_filename_pre = Inferred_True_filename/Inferred_filename
    else:
        BinPRE_filename_pre = 0
    
    if (BinPRE_filename_rec + BinPRE_filename_pre) > 0:
        BinPRE_filename_F1 = (2 * BinPRE_filename_rec * BinPRE_filename_pre) / (BinPRE_filename_rec + BinPRE_filename_pre)
    else:
        BinPRE_filename_F1 = 0

    no_Average_Pre = Average_Pre
    no_Average_Rec = Average_Rec
    no_F1_score = F1_score

    with open(config.Evaluation_Res, "a") as file:
        file.write("\n\n\Semantic-Function Evaluation Part For BinPRE(no validation)---------------------------------\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n\n")
        file.write(f"no_BinPRE_Command_pre:{no_BinPRE_Command_pre}\n")
        file.write(f"no_BinPRE_Command_rec:{no_BinPRE_Command_rec}\n")
        file.write(f"no_BinPRE_Command_F1:{no_BinPRE_Command_F1}\n\n")
        file.write(f"\n")
        file.write(f"no_BinPRE_Command_pre:{BinPRE_Command_pre}\n")
        file.write(f"no_BinPRE_Command_rec:{BinPRE_Command_rec}\n")
        file.write(f"no_BinPRE_Command_F1:{BinPRE_Command_F1}\n")
        file.write(f"\nno_BinPRE_Length_pre:{BinPRE_Length_pre}\n")
        file.write(f"no_BinPRE_Length_rec:{BinPRE_Length_rec}\n")
        file.write(f"no_BinPRE_Length_F1:{BinPRE_Length_F1}\n")
        file.write(f"\nno_BinPRE_Delim_pre:{BinPRE_Delim_pre}\n")
        file.write(f"no_BinPRE_Delim_rec:{BinPRE_Delim_rec}\n")
        file.write(f"no_BinPRE_Delim_F1:{BinPRE_Delim_F1}\n")
        file.write(f"no_delim_groudtruth:{delim_groudtruth}\n")
        file.write(f"\nno_BinPRE_aligned_pre:{BinPRE_aligned_pre}\n")
        file.write(f"no_BinPRE_aligned_rec:{BinPRE_aligned_rec}\n")
        file.write(f"no_BinPRE_aligned_F1:{BinPRE_aligned_F1}\n")
        file.write(f"no_aligned_groudtruth:{aligned_groudtruth}\n")
        file.write(f"\nno_BinPRE_filename_pre:{BinPRE_filename_pre}\n")
        file.write(f"no_BinPRE_filename_rec:{BinPRE_filename_rec}\n")
        file.write(f"no_BinPRE_filename_F1:{BinPRE_filename_F1}\n")
        file.write(f"no_filename_groudtruth:{filename_groudtruth}\n")

    print("\n\n\nSemantic-Functions Evaluation Part For BinPRE(Validated)---------------------------------")
    

    '''Semantic-Function'''
    semantic_usedPre,msg_Pre, msg_Rec =0,0,0

    BinPRE_length_correct = 0
    BinPRE_command_correct = 0
    BinPRE_length_count = 0
    BinPRE_command_count = 0

    True_delim_groudtruth = 0
    Inferred_delim = 0
    Inferred_True_delim = 0
    delim_groudtruth = set()

    True_aligned_groudtruth = 0
    Inferred_aligned = 0
    Inferred_True_aligned = 0
    aligned_groudtruth = set()

    True_filename_groudtruth = 0
    Inferred_filename = 0
    Inferred_True_filename = 0
    filename_groudtruth = set()

    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]

        if config.evaluation_mode == 'index':
            msg_semanticTruth = Semantic_Functions_Groundtruth[i]
            msg_fieldTruth = Semantic_Groundtruth[i]
        else:
            msg_semanticTruth = Semantic_Functions_Groundtruth[msg_command]
            msg_fieldTruth = Semantic_Groundtruth[msg_command]

        msg_semanticRes = message_Result[i].field_funcs

        for f,r in msg_semanticRes.items():
            if config.semantic_Functions[0] in r:
                BinPRE_command_count += 1
                if f == config.commandOffset:
                    BinPRE_command_correct += 1
            if config.semantic_Functions[1] in r:
                BinPRE_length_count += 1
                if f == config.lengthOffset:
                    BinPRE_length_correct += 1
        
        for f,r in msg_semanticTruth.items():
            if (config.semantic_Functions[2] in msg_semanticTruth[f]):
                True_delim_groudtruth += 1
                delim_groudtruth.add(f)
            if (config.semantic_Functions[4] in msg_semanticTruth[f]):
                True_aligned_groudtruth += 1
                aligned_groudtruth.add(f)
            if (config.semantic_Functions[5] in msg_semanticTruth[f]):
                True_filename_groudtruth += 1
                filename_groudtruth.add(f)


        for f,r in msg_semanticRes.items():

            if config.semantic_Functions[2] in r:
                Inferred_delim += 1
                if (f in msg_semanticTruth) and (config.semantic_Functions[2] in msg_semanticTruth[f]):
                    Inferred_True_delim += 1
            
            if config.semantic_Functions[4] in r:
                Inferred_aligned += 1
                if (f in msg_semanticTruth) and (config.semantic_Functions[4] in msg_semanticTruth[f]):
                    Inferred_True_aligned += 1
            
            if config.semantic_Functions[5] in r:
                Inferred_filename += 1
                if (f in msg_semanticTruth) and (config.semantic_Functions[5] in msg_semanticTruth[f]):
                    Inferred_True_filename += 1
            

        print(f"Msg {i} semantic evaluation:***\n")
        print(f"msg_semanticTruth:{msg_semanticTruth}")
        print(f"msg_semanticRes:{msg_semanticRes}\n")

        msg_pre, msg_rec= metrix_Cal_Func(msg_semanticTruth,msg_semanticRes, message_Result[i].fields, msg_len, msg_fieldTruth)
        print(f"msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        
        msg_Pre += msg_pre
        msg_Rec += msg_rec
        

    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    if (Average_Pre + Average_Rec) > 0:
        F1_score = (2 * Average_Pre * Average_Rec) / (Average_Pre + Average_Rec)
    else:
        F1_score = 0
    

    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1_score:{F1_score}")
    
    BinPRE_Command_rec = BinPRE_command_correct/len(payload_message)
    BinPRE_Length_rec = BinPRE_length_correct/len(payload_message)
    if BinPRE_command_count>0:
        BinPRE_Command_pre = BinPRE_command_correct/BinPRE_command_count
        if (BinPRE_Command_pre + BinPRE_Command_rec) > 0:
            BinPRE_Command_F1 = (2 * BinPRE_Command_pre * BinPRE_Command_rec) / (BinPRE_Command_pre + BinPRE_Command_rec) 
        else:
            BinPRE_Command_F1 = 0
    else:
        BinPRE_Command_pre = 0
        BinPRE_Command_F1 = 0
    if BinPRE_length_count>0:
        BinPRE_Length_pre = BinPRE_length_correct / BinPRE_length_count
        if (BinPRE_Length_pre + BinPRE_Length_rec) > 0:
            BinPRE_Length_F1 = (2 * BinPRE_Length_pre * BinPRE_Length_rec) / (BinPRE_Length_pre + BinPRE_Length_rec)
        else:
            BinPRE_Length_F1 = 0
    else:
        BinPRE_Length_pre = 0
        BinPRE_Length_F1 = 0
    if True_delim_groudtruth > 0:
        BinPRE_Delim_rec = Inferred_True_delim/True_delim_groudtruth
    else:
        BinPRE_Delim_rec = 0
    
    if Inferred_delim > 0:
        BinPRE_Delim_pre = Inferred_True_delim/Inferred_delim
    else:
        BinPRE_Delim_pre = 0
    
    if (BinPRE_Delim_rec + BinPRE_Delim_pre) > 0:
        BinPRE_Delim_F1 = (2 * BinPRE_Delim_rec * BinPRE_Delim_pre) / (BinPRE_Delim_rec + BinPRE_Delim_pre)
    else:
        BinPRE_Delim_F1 = 0
    if True_aligned_groudtruth > 0:
        BinPRE_aligned_rec = Inferred_True_aligned/True_aligned_groudtruth
    else:
        BinPRE_aligned_rec = 0
    
    if Inferred_aligned > 0:
        BinPRE_aligned_pre = Inferred_True_aligned/Inferred_aligned
    else:
        BinPRE_aligned_pre = 0
    
    if (BinPRE_aligned_rec + BinPRE_aligned_pre) > 0:
        BinPRE_aligned_F1 = (2 * BinPRE_aligned_rec * BinPRE_aligned_pre) / (BinPRE_aligned_rec + BinPRE_aligned_pre)
    else:
        BinPRE_aligned_F1 = 0
    if True_filename_groudtruth > 0:
        BinPRE_filename_rec = Inferred_True_filename/True_filename_groudtruth
    else:
        BinPRE_filename_rec = 0
    
    if Inferred_filename > 0:
        BinPRE_filename_pre = Inferred_True_filename/Inferred_filename
    else:
        BinPRE_filename_pre = 0
    
    if (BinPRE_filename_rec + BinPRE_filename_pre) > 0:
        BinPRE_filename_F1 = (2 * BinPRE_filename_rec * BinPRE_filename_pre) / (BinPRE_filename_rec + BinPRE_filename_pre)
    else:
        BinPRE_filename_F1 = 0

    print(f"BinPRE_Command_pre:{BinPRE_Command_pre}")
    print(f"BinPRE_Command_rec:{BinPRE_Command_rec}")
    print(f"BinPRE_Length_pre:{BinPRE_Length_pre}")
    print(f"BinPRE_Length_rec:{BinPRE_Length_rec}")

    with open(config.Evaluation_Res, "a") as file:
        file.write("\n\n\Semantic-Function Evaluation Part For BinPRE(Validated)---------------------------------\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n")
        file.write(f"\n")
        file.write(f"BinPRE_Command_pre:{BinPRE_Command_pre}\n")
        file.write(f"BinPRE_Command_rec:{BinPRE_Command_rec}\n")
        file.write(f"BinPRE_Command_F1:{BinPRE_Command_F1}\n")
        file.write(f"\nBinPRE_Length_pre:{BinPRE_Length_pre}\n")
        file.write(f"BinPRE_Length_rec:{BinPRE_Length_rec}\n")
        file.write(f"BinPRE_Length_F1:{BinPRE_Length_F1}\n")
        file.write(f"\nBinPRE_Delim_pre:{BinPRE_Delim_pre}\n")
        file.write(f"BinPRE_Delim_rec:{BinPRE_Delim_rec}\n")
        file.write(f"BinPRE_Delim_F1:{BinPRE_Delim_F1}\n")
        file.write(f"delim_groudtruth:{delim_groudtruth}\n")
        file.write(f"\nBinPRE_aligned_pre:{BinPRE_aligned_pre}\n")
        file.write(f"BinPRE_aligned_rec:{BinPRE_aligned_rec}\n")
        file.write(f"BinPRE_aligned_F1:{BinPRE_aligned_F1}\n")
        file.write(f"aligned_groudtruth:{aligned_groudtruth}\n")
        file.write(f"\nBinPRE_filename_pre:{BinPRE_filename_pre}\n")
        file.write(f"BinPRE_filename_rec:{BinPRE_filename_rec}\n")
        file.write(f"BinPRE_filename_F1:{BinPRE_filename_F1}\n")
        file.write(f"filename_groudtruth:{filename_groudtruth}\n")

    return no_Average_Pre, no_Average_Rec, no_F1_score, Average_Pre, Average_Rec, F1_score

def Polyglot_SemanticEvaluator(payload_message, Polyglot_length_Res, Polyglot_command_Res, Polyglot_separator_Res, commandOffset):
    polyglot_length_correct = 0
    polyglot_command_correct = 0
    polyglot_length_count = 0
    polyglot_command_count = 0

    True_delim_groudtruth = 0
    Inferred_delim = 0
    Inferred_True_delim = 0
    delim_groudtruth = set()

    print("\n\n\nSemantic Evaluation Part For Polyglot---------------------------------")
    for i in range(0,len(payload_message)):
        polyglot_length_count += len(Polyglot_length_Res[i])
        if Polyglot_command_Res[i] is not None and len(Polyglot_command_Res[i])>0:
            polyglot_command_count += len(Polyglot_command_Res[i])
        else:
            polyglot_command_count = 0
        Inferred_delim += len(Polyglot_separator_Res[i])

        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]

        if config.evaluation_mode == 'index':
            msg_semanticTruth = Semantic_Functions_Groundtruth[i]
        else:
            msg_semanticTruth = Semantic_Functions_Groundtruth[msg_command]
        

        if config.lengthOffset in Polyglot_length_Res[i]:
            polyglot_length_correct += 1
        if commandOffset in Polyglot_command_Res[i]:
            polyglot_command_correct += 1

        for k, v in msg_semanticTruth.items():
            v = [v]
            
            if config.semantic_Functions[2] in v:
                True_delim_groudtruth += 1
                delim_groudtruth.add(k)
                if k in Polyglot_separator_Res[i]:
                    Inferred_True_delim += 1
                    

        
    Polyglot_Command_rec = polyglot_command_correct/len(payload_message)
    Polyglot_Length_rec = polyglot_length_correct/len(payload_message)
    if polyglot_command_count > 0 :
        Polyglot_Command_pre = polyglot_command_correct/polyglot_command_count
        if (Polyglot_Command_pre + Polyglot_Command_rec) > 0 : 
            Polyglot_Command_F1 = (2 * Polyglot_Command_pre * Polyglot_Command_rec) / (Polyglot_Command_pre + Polyglot_Command_rec)
        else:
            Polyglot_Command_F1 = 0
    else:
        Polyglot_Command_pre = 0
        Polyglot_Command_F1 = 0

    if polyglot_length_count > 0:
        Polyglot_Length_pre = polyglot_length_correct/polyglot_length_count
        if (Polyglot_Length_pre + Polyglot_Length_rec) > 0:
            Polyglot_Length_F1 = (2 * Polyglot_Length_pre * Polyglot_Length_rec) / (Polyglot_Length_pre + Polyglot_Length_rec)
        else:
            Polyglot_Length_F1 = 0
    else:
        Polyglot_Length_pre = 0
        Polyglot_Length_F1 = 0
    
    if True_delim_groudtruth > 0:
        Polyglot_Delim_rec = Inferred_True_delim/True_delim_groudtruth
    else:
        Polyglot_Delim_rec = 0
    
    if Inferred_delim > 0:
        Polyglot_Delim_pre = Inferred_True_delim/Inferred_delim
    else:
        Polyglot_Delim_pre = 0
    
    if (Polyglot_Delim_rec + Polyglot_Delim_pre) > 0:
        Polyglot_Delim_F1 = (2 * Polyglot_Delim_rec * Polyglot_Delim_pre) / (Polyglot_Delim_rec + Polyglot_Delim_pre)
    else:
        Polyglot_Delim_F1 = 0

    with open(config.Evaluation_bo_Res, "a") as file:
        file.write(f"\n\n\nPolyglot_Command_pre:{Polyglot_Command_pre}\n")
        file.write(f"Polyglot_Command_rec:{Polyglot_Command_rec}\n")
        file.write(f"Polyglot_Command_F1:{Polyglot_Command_F1}\n")

        file.write(f"\n\nPolyglot_Tupni_Length_pre:{Polyglot_Length_pre}\n")
        file.write(f"Polyglot_Tupni_Length_rec:{Polyglot_Length_rec}\n")
        file.write(f"Polyglot_Tupni_Length_F1:{Polyglot_Length_F1}\n")

        file.write(f"\n\Polyglot_Delim_pre:{Polyglot_Delim_pre}\n")
        file.write(f"Polyglot_Delim_rec:{Polyglot_Delim_rec}\n")
        file.write(f"Polyglot_Delim_F1:{Polyglot_Delim_F1}\n")






