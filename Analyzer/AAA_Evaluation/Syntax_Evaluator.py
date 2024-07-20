import sys
sys.path.append('/home/linuxbrew/pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/BinPRE/Analyzer/config')
import config

Syntax_Groundtruth = config.Syntax_Groundtruth

def Processing(synRes,msg_len):
    msg_syntaxRes = set()
    for field in synRes:
        boundary1 = int(field.split(',')[0])-1
        boundary2 = int(field.split(',')[-1])
        msg_syntaxRes.add(boundary1)
        msg_syntaxRes.add(boundary2)
    
    return msg_syntaxRes

def Processing_tree(AutoFormat_ftree,msg_len):

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


def metrix_Cal(msg_syntaxTruth,msg_syntaxRes,msg_len):
    correct_boundary_number = 0
    inferred_true_field_coundary_number = 0
    msg_syntaxTruth = set(msg_syntaxTruth)
    msg_syntaxTruth.add(int(msg_len-1))
    msg_syntaxRes = set(msg_syntaxRes)
    msg_syntaxRes.add(int(msg_len-1))

    over_seg = 0
    under_seg = 0

    for i in range(-1,msg_len):
        if i in msg_syntaxTruth:
            if i in msg_syntaxRes:
                inferred_true_field_coundary_number += 1
                correct_boundary_number += 1
            else:
                under_seg += 1
        else:
            if i not in msg_syntaxRes:
                correct_boundary_number += 1
            else:
                over_seg += 1

    msg_accr = correct_boundary_number/(msg_len+1)
    msg_pre = inferred_true_field_coundary_number/len(msg_syntaxRes)
    msg_rec = inferred_true_field_coundary_number/len(msg_syntaxTruth)

    perfect_inferred = 0
    msg_syntaxTruth = sorted(list(msg_syntaxTruth))

    msg_syntaxTruth = sorted(msg_syntaxTruth, key=int)

    print(f"^^^^\nmsg_syntaxRes:{msg_syntaxRes}")
    print(f"msg_syntaxTruth:{msg_syntaxTruth}\n\n")


    for i in range(0,len(msg_syntaxTruth)-1):
        field_boundary1 = msg_syntaxTruth[i]
        field_boundary2 = msg_syntaxTruth[i+1]
        perf_flag = 0
        print(f"field_boundary1:{field_boundary1}\tfield_boundary2:{field_boundary2}")
        
        if (field_boundary1 in msg_syntaxRes) and (field_boundary2 in msg_syntaxRes):
            perf_flag = 1
            for j in range(field_boundary1+1,field_boundary2):
                if (j in msg_syntaxRes):
                    perf_flag = 0
                    break
        else:
            perf_flag = 0
        
        if perf_flag == 1:
            perfect_inferred += 1
    
    msg_perf = perfect_inferred/(len(msg_syntaxTruth)-1)

    if len(msg_syntaxRes) == 2:
        msg_pre = 0
        msg_rec = 0

    return msg_accr, msg_pre, msg_rec,msg_perf, under_seg, over_seg#, handled_unused_over_seg


def BinPREEvaluator(payload_message, Pre_message_Result, message_Result, commandOffset, Msg_used):
    print("\n\n\nEvaluation Part For BinPRE(no validation)---------------------------------")
    msg_Accr, msg_Pre, msg_Rec,msg_Perf =0,0,0,0

    Under_Seg, Over_Seg = 0,0
    Handled_Unused_Over_Seg = 0
    Error_Handled_Unused_Under_Seg = 0


    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        msg_used = Msg_used[i]
        handled_unused_over_seg = 0 
        error_handled_unused_under_seg = 0
        boundaries = Pre_message_Result[i].boundaries
        unused_boundaries = []

        boundaries = sorted(boundaries, key=int)
        
        for b in range(0,len(boundaries)-1):#[-1,2]
            b_s = boundaries[b] + 1#0
            b_e = boundaries[b+1]#2

            curr_bf = ','.join(str(s) for s in range(b_s, b_e+1))#'0,1,2'

            if curr_bf not in msg_used:
                for bb in range(b_s, b_e):#(0,2)
                    unused_boundaries.append(bb)

        print(f"unused_boundaries:{unused_boundaries}")


        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]
        if config.evaluation_mode == 'index':
            msg_syntaxTruth = Syntax_Groundtruth[i]
        else:
            msg_syntaxTruth = Syntax_Groundtruth[msg_command]

        msg_syntaxTruth = set(msg_syntaxTruth)
        msg_syntaxTruth.add(int(msg_len-1))

        for tb in range(-1,msg_len-1):
            if tb not in msg_syntaxTruth:
                if (tb not in boundaries) and (tb in unused_boundaries):
                    print(f"tb:{tb}")
                    handled_unused_over_seg += 1
        
        for tb in range(-1,msg_len-1):
            if tb in msg_syntaxTruth:
                if (tb not in boundaries) and (tb in unused_boundaries):
                    print(f"under_tb:{tb}")
                    error_handled_unused_under_seg += 1


        msg_accr, msg_pre, msg_rec,msg_perf, under_seg, over_seg = metrix_Cal(msg_syntaxTruth, Pre_message_Result[i].boundaries,msg_len)
        print(f"Msg {i} evaluation:***\n")
        print(f"msg_accr: {msg_accr}, msg_pre:{msg_pre}, msg_rec:{msg_rec}, msg_perf:{msg_perf}\n")
        print(f"under_seg: {under_seg}, over_seg:{over_seg}\n")
        
        msg_Accr += msg_accr
        msg_Pre += msg_pre
        msg_Rec += msg_rec
        msg_Perf += msg_perf

        Under_Seg += under_seg
        Over_Seg += over_seg
        Handled_Unused_Over_Seg += handled_unused_over_seg
        Error_Handled_Unused_Under_Seg += error_handled_unused_under_seg

    Average_Accr = msg_Accr/len(payload_message)
    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    Average_Perf = msg_Perf/len(payload_message)
    F1_score = 2 * Average_Pre * Average_Rec / (Average_Pre + Average_Rec)


    print(f"Average_Accr:{Average_Accr}")
    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1-score:{F1_score}")
    print(f"Average_Perf:{Average_Perf}")
    print(f"******************")
    print(f"Under_Seg:{Under_Seg}")
    print(f"Over_Seg:{Over_Seg}")
    print(f"handle_unused's Over_Seg:{Handled_Unused_Over_Seg}\n")
    print(f"Error_Handled_Unused_Under_Seg:{Error_Handled_Unused_Under_Seg}\n")


    with open(config.Evaluation_Res, "a") as file:
        file.write("\n\n\nEvaluation Part For BinPRE---------------------------------\n")
        file.write(f"Average_Accr:{Average_Accr}\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n")
        file.write(f"Average_Perf:{Average_Perf}\n")
        file.write(f"******************\n")
        file.write(f"Under_Seg:{Under_Seg}\n")
        file.write(f"Over_Seg:{Over_Seg}\n")
        file.write(f"handle_unused's Over_Seg:{Handled_Unused_Over_Seg}\n")
        file.write(f"Error_Handled_Unused_Under_Seg:{Error_Handled_Unused_Under_Seg}\n")

    return Average_Accr, F1_score, Average_Perf

def PolyglotEvaluator(payload_message,Polyglot_Syntax,commandOffset):

    print("\n\n\nEvaluation Part for Polyglot---------------------------------")

    msg_Accr, msg_Pre, msg_Rec,msg_Perf =0,0,0,0

    Under_Seg, Over_Seg = 0,0

    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]
        if config.evaluation_mode == 'index':
            msg_syntaxTruth = Syntax_Groundtruth[i]
        else:
            msg_syntaxTruth = Syntax_Groundtruth[msg_command]

        msg_syntaxRes = Processing(Polyglot_Syntax[i],msg_len)

        msg_accr, msg_pre, msg_rec,msg_perf, under_seg, over_seg= metrix_Cal(msg_syntaxTruth,msg_syntaxRes,msg_len)
        print(f"Msg {i} evaluation:***\n")
        print(f"msg_accr: {msg_accr}, msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        print(f"under_seg: {under_seg}, over_seg:{over_seg}\n")
        
        msg_Accr += msg_accr
        msg_Pre += msg_pre
        msg_Rec += msg_rec
        msg_Perf += msg_perf

        Under_Seg += under_seg
        Over_Seg += over_seg

    Average_Accr = msg_Accr/len(payload_message)
    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    F1_score = 2 * Average_Pre * Average_Rec / (Average_Pre + Average_Rec)
    Average_Perf = msg_Perf/len(payload_message)


    print(f"Average_Accr:{Average_Accr}")
    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1-score:{F1_score}")
    print(f"Average_Perf:{Average_Perf}")
    print(f"******************")
    print(f"Under_Seg:{Under_Seg}")
    print(f"Over_Seg:{Over_Seg}")

    with open(config.Evaluation_bo_Res, "a") as file:
        file.write("\n\n\nEvaluation Part For Polyglot_Syntax---------------------------------\n")
        file.write(f"Average_Accr:{Average_Accr}\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n")
        file.write(f"Average_Perf:{Average_Perf}\n")
        file.write(f"******************\n")
        file.write(f"Under_Seg:{Under_Seg}\n")
        file.write(f"Over_Seg:{Over_Seg}\n")



def AutoFormatEvaluator(payload_message,commandOffset,AutoFormat_ftrees):
    Autoformat_syntaxRes = {}
    print("\n\n\nEvaluation Part For AutoFormat---------------------------------")

    msg_Accr, msg_Pre, msg_Rec, msg_Perf =0,0,0,0

    Under_Seg, Over_Seg = 0,0

    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        print(f"msg_len:{msg_len}")
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]
        if config.evaluation_mode == 'index':
            msg_syntaxTruth = Syntax_Groundtruth[i]
        else:
            msg_syntaxTruth = Syntax_Groundtruth[msg_command]

        msg_syntaxRes = Processing_tree(AutoFormat_ftrees[i],msg_len)
        
        Autoformat_syntaxRes[i] = msg_syntaxRes

        msg_accr, msg_pre, msg_rec,msg_perf, under_seg, over_seg= metrix_Cal(msg_syntaxTruth,msg_syntaxRes,msg_len)
        print(f"Msg {i} evaluation:***\n")
        print(f"msg_accr: {msg_accr}, msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        print(f"under_seg: {under_seg}, over_seg:{over_seg}\n")
        
        msg_Accr += msg_accr
        msg_Pre += msg_pre
        msg_Rec += msg_rec
        msg_Perf += msg_perf

        Under_Seg += under_seg
        Over_Seg += over_seg

    Average_Accr = msg_Accr/len(payload_message)
    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    F1_score = 2 * Average_Pre * Average_Rec / (Average_Pre + Average_Rec)
    Average_Perf = msg_Perf/len(payload_message)


    print(f"Average_Accr:{Average_Accr}")
    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1-score:{F1_score}")
    print(f"Average_Perf:{Average_Perf}")
    print(f"******************")
    print(f"Under_Seg:{Under_Seg}")
    print(f"Over_Seg:{Over_Seg}")

    with open(config.Evaluation_bo_Res, "a") as file:
        file.write("\n\n\nEvaluation Part For AutoFormat_Syntax---------------------------------\n")
        file.write(f"Average_Accr:{Average_Accr}\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n")
        file.write(f"Average_Perf:{Average_Perf}\n")
        file.write(f"******************\n")
        file.write(f"Under_Seg:{Under_Seg}\n")
        file.write(f"Over_Seg:{Over_Seg}\n")

    return Autoformat_syntaxRes

def TupniEvaluator(payload_message,Tupni_Syntax,commandOffset):

    print("\n\n\nEvaluation Part for Tupni---------------------------------")

    msg_Accr, msg_Pre, msg_Rec,msg_Perf =0,0,0,0

    Under_Seg, Over_Seg = 0,0

    for i in range(0,len(payload_message)):
        msg_i = payload_message[i]
        msg_len = len(msg_i)
        command_start = int(commandOffset.split(',')[0])
        command_end = int(commandOffset.split(',')[-1])+1
        msg_command = payload_message[i][command_start:command_end]
        if config.evaluation_mode == 'index':
            msg_syntaxTruth = Syntax_Groundtruth[i]
        else:
            msg_syntaxTruth = Syntax_Groundtruth[msg_command]
        msg_syntaxRes = Processing(Tupni_Syntax[i],msg_len)

        msg_accr, msg_pre, msg_rec,msg_perf, under_seg, over_seg= metrix_Cal(msg_syntaxTruth,msg_syntaxRes,msg_len)
        print(f"Msg {i} evaluation:***\n")
        print(f"msg_accr: {msg_accr}, msg_pre:{msg_pre}, msg_rec:{msg_rec}\n")
        print(f"under_seg: {under_seg}, over_seg:{over_seg}\n")
        
        msg_Accr += msg_accr
        msg_Pre += msg_pre
        msg_Rec += msg_rec
        msg_Perf += msg_perf

        Under_Seg += under_seg
        Over_Seg += over_seg

    Average_Accr = msg_Accr/len(payload_message)
    Average_Pre = msg_Pre/len(payload_message)
    Average_Rec = msg_Rec/len(payload_message)
    F1_score = 2 * Average_Pre * Average_Rec / (Average_Pre + Average_Rec)
    Average_Perf = msg_Perf/len(payload_message)


    print(f"Average_Accr:{Average_Accr}")
    print(f"Average_Pre:{Average_Pre}")
    print(f"Average_Rec:{Average_Rec}")
    print(f"F1-score:{F1_score}")
    print(f"Average_Perf:{Average_Perf}")
    print(f"******************")
    print(f"Under_Seg:{Under_Seg}")
    print(f"Over_Seg:{Over_Seg}")

    with open(config.Evaluation_bo_Res, "a") as file:
        file.write("\n\n\nEvaluation Part For Tupni_Syntax---------------------------------\n")
        file.write(f"Average_Accr:{Average_Accr}\n")
        file.write(f"Average_Pre:{Average_Pre}\n")
        file.write(f"Average_Rec:{Average_Rec}\n")
        file.write(f"F1_score:{F1_score}\n")
        file.write(f"Average_Perf:{Average_Perf}\n")
        file.write(f"******************\n")
        file.write(f"Under_Seg:{Under_Seg}\n")
        file.write(f"Over_Seg:{Over_Seg}\n")

