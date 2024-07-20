import re
from collections import Counter
import config
import time
import sys
import math
import statistics
import numpy as np
import Similarity



def Command_Exploration(message_Result, payload_message):
    msg_nums = len(payload_message)
    template_format = message_Result[0].fields
    candidates = []
    # pick command candidates
    for i in range(len(payload_message)):
        for k,v in message_Result[i].field_funcs.items():
            if config.semantic_Functions[0] in v:
                candidates.append(k)
        for k,v in message_Result[i].field_types.items():
            if config.semantic_Types[1] in v:
                candidates.append(k)
            if len(v) == 0:
                candidates.append(k)
        
    print(f"candidates:{candidates}")

    alignmentInCluster = {}
    alignmentBetweenClusters = {}

    max_score = -100
    min_diff = 100
    min_size = 100
    Command_field = ''

    # Format_based Exploration
    for template_field in template_format:
        template_start = int(template_field.split(',')[0])
        template_end = int(template_field.split(',')[-1])

        clusters = {}
        alignmentInCluster_score = 0
        alignmentBetweenClusters_score = 0

        # calculat similarity in and betweem clusters
        for i in range(msg_nums):
            curr_command = payload_message[i][template_start:template_end+1]
            if curr_command not in clusters:
                clusters[curr_command] = []
            clusters[curr_command].append(i)
 
        clusters_nums = len(clusters)

        for k, v in clusters.items():
            if len(v) == 1:
                clusters_nums -= 1
                continue
            curr_format = []
            for a in v:
                curr_format.append(message_Result[a].boundaries)

            total_score = 0
            pair_count = 0
            for i in range(len(curr_format)):
                for j in range(i+1, len(curr_format)):
                    seq1 = curr_format[i]
                    seq2 = curr_format[j]
                    score = Similarity.needleman_wunsch(seq1, seq2)
                    total_score += score
                    pair_count += 1

            average_score = total_score / pair_count
            alignmentInCluster_score += average_score

        cluster_keys = list(clusters.keys())
        cluster_count = len(cluster_keys)

        for i in range(cluster_count):
            for j in range(i+1, cluster_count):
                cluster1 = clusters[cluster_keys[i]]
                cluster2 = clusters[cluster_keys[j]]

                total_score = 0
                pair_count = 0
                for seq1 in cluster1:
                    seq1 = message_Result[seq1].boundaries
                    for seq2 in cluster2:
                        seq2 = message_Result[seq2].boundaries
                        score = Similarity.needleman_wunsch(seq1, seq2)
                        total_score += score
                        pair_count += 1

                average_score = total_score / pair_count if pair_count > 0 else 0
                alignmentBetweenClusters_score += average_score

        alignmentInCluster_avg = alignmentInCluster_score / clusters_nums if clusters_nums > 0 else 0
        alignmentBetweenClusters_avg = alignmentBetweenClusters_score / (cluster_count * (cluster_count - 1) / 2) if cluster_count > 1 else 0
        
        print(f"alignmentInCluster_avg:{alignmentInCluster_avg}")
        print(f"alignmentBetweenClusters_avg:{alignmentBetweenClusters_avg}")


        print(f"----- template_field {k}")
        if max_score < alignmentInCluster_avg:
            if template_field not in candidates or config.notConformCommand(message_Result,template_field,template_format):
                if template_field not in candidates:
                    print(f"template_field {k} is not in candidates")
                if config.notConformCommand(message_Result,template_field,template_format):
                    print(f"template_field {k} does not conform with the command")
                continue
            max_score = alignmentInCluster_avg
            Command_field = template_field
            min_diff = alignmentBetweenClusters_avg
            min_size = template_field.count(',')
        elif max_score == alignmentInCluster_avg:
            #less similarity between different clusters.
            if alignmentBetweenClusters_avg <= min_diff and (template_field.count(',') < min_size):
                min_diff = alignmentBetweenClusters_avg
                Command_field = template_field
                min_size = template_field.count(',')

        alignmentInCluster[template_field] = alignmentInCluster_avg
        alignmentBetweenClusters[template_field] = alignmentBetweenClusters_avg
    
    for k,v in alignmentInCluster.items():
        print(f"template_field:{k}, alignmentInCluster:{alignmentInCluster[k]}, alignmentBetweenCluster:{alignmentBetweenClusters[k]}")


    return Command_field



def Clustering(payload_message, msg_nums, Command_pos, Command_size):
    Clusters = {}

    for i in range(0,msg_nums):
        message = payload_message[i]
        command = message[Command_pos : Command_pos + Command_size]
        if command not in Clusters:
            Clusters[command] = []
        Clusters[command].append(i)
    
    return Clusters

def calculate_shannon_entropy(data):
    symbol_counts = Counter(data)
    total_symbols = len(data)
    symbol_probabilities = [count / total_symbols for count in symbol_counts.values()]
    entropy = -sum(p * math.log2(p) for p in symbol_probabilities)

    return entropy

def Type_Validation(Command_field, Command_size,message_Result, v):

    Shannon_value = []
    for index in v:
        print(f"\tmsg {index}")
        field_Types = message_Result[index].field_types
        i = 0
        fields_value_set = []
        for f, types in field_Types.items():
            if f == Command_field:
                field_Types[f] = [config.semantic_Types[1]]
                fields_value_set.append([])
                i += 1
                continue
            field_value_set = []

            # Obtain the value of the field on this position
            for j in v:
                if i >= len(message_Result[j].fields):
                    continue
                j_start = int(message_Result[j].fields[i].split(',')[0])
                j_end = int(message_Result[j].fields[i].split(',')[-1])
                field_value = int.from_bytes(message_Result[j].payload[j_start : j_end+1], byteorder=config.endian)   
                if field_value:
                    field_value_set.append(field_value)
            
            fields_value_set.append(field_value_set)
            i += 1
        # calculate entropies for each field in the message{index}
        fields_entropies = [calculate_shannon_entropy(field) for field in fields_value_set]
        print(f"fields_entropies:{fields_entropies}")
        median_value = statistics.median(fields_entropies)

        fields_entropies = list(zip(message_Result[index].fields, fields_entropies))

        '''Validate for Used Field'''
        for (f, entro) in fields_entropies:
            if f == Command_field:
                continue
            print(f"f : {f}, entro : {entro}")
            f_types = message_Result[index].field_types[f]
            if (entro > median_value) and (config.semantic_Types[0] in f_types):
                f_types.remove(config.semantic_Types[0])
            
            if (len(v)>5) and (entro < median_value):
                if config.semantic_Types[4] in f_types:
                    f_types.remove(config.semantic_Types[4])
        
        
        '''Classify For Unused Field'''

        boundaries = message_Result[index].boundaries
        for b_i in range(0,len(boundaries)-1):
            f_i = ','.join(str(i) for i in range(boundaries[b_i]+1, boundaries[b_i+1]+1))
            #used
            if f_i in message_Result[index].field_types:
                continue
            #unused
            field_value_set = []

            for j in v:
                if b_i >= len(message_Result[j].boundaries):
                    continue
                j_start = int(message_Result[j].boundaries[b_i]+1)
                if b_i+1 < len(message_Result[j].boundaries):
                    j_end = int(message_Result[j].boundaries[b_i+1]+1)
                    field_value = int.from_bytes(message_Result[j].payload[j_start : j_end+1], byteorder=config.endian)   
                else:
                    field_value = int.from_bytes(message_Result[j].payload[j_start : ], byteorder=config.endian)   
                field_value_set.append(field_value)
            
            shannon_bi = calculate_shannon_entropy(field_value_set)

            if len(v) < 5:
                # The number of messages within the current cluster is too small to calculate the information entropy.
                if shannon_bi == -0.0:
                    message_Result[index].field_types[f_i] = [config.semantic_Types[0]]
                elif shannon_bi < median_value:
                    message_Result[index].field_types[f_i] = [config.semantic_Types[3]]
                elif shannon_bi > median_value:
                    message_Result[index].field_types[f_i] = [config.semantic_Types[4]]
            else:
                if f_i.count(',')>3:
                    message_Result[index].field_types[f_i] =[config.semantic_Types[4]]
                    continue
                min_dist = 100
                similari_f = f_i
                for (f, entro) in fields_entropies:

                    if min_dist > (abs(shannon_bi-entro)):
                        similari_f = f
                        min_dist = abs(shannon_bi-entro)
                
                message_Result[index].field_types[f_i] = message_Result[index].field_types[similari_f]
            

def Function_Validation(Command_field, Command_size,message_Result, v):
    
    for index in v:       
        field_Functions = message_Result[index].field_funcs
 
        checksum_size = 0
        for f, functions in field_Functions.items():
            if config.semantic_Functions[3] in functions:
                    checksum_size += f.count(',') + 1

        for f, functions in field_Functions.items():

            f_start = int(f.split(',')[0])
            f_end = int(f.split(',')[-1])
            
            f_value = int.from_bytes(message_Result[index].payload[f_start : f_end+1], byteorder=config.endian)

            validated_functions = []

            

            for func in functions:
                # Command
                if func == config.semantic_Functions[0] and f != Command_field:
                    continue
                # Length
                if func == config.semantic_Functions[1]:
                    if config.semantic_Types[3] not in message_Result[index].field_types[f]:
                        continue
                    direction_pos = f_end + f_value
                    if config.notConformLength(direction_pos, message_Result, index, f_value, f_end, checksum_size):
                        continue
                # Delim
                if func == config.semantic_Functions[2]:

                    if ((config.semantic_Types[0] not in message_Result[index].field_types[f]) and \
                    (config.semantic_Types[1] not in message_Result[index].field_types[f])) or \
                        (f.count(',')>2):
                        continue
                
                # Checksum
                if func == config.semantic_Functions[3]:
                    if (config.semantic_Types[3] not in message_Result[index].field_types[f]) and \
                    (len(message_Result[index].field_types[f]) > 0):
                        continue

                # Aligned
                if func == config.semantic_Functions[4]:
                    if (config.semantic_Types[4] not in message_Result[index].field_types[f]) and (config.semantic_Types[1] not in message_Result[index].field_types[f]):
                        continue
                # Filename
                if func == config.semantic_Functions[5]:
                    if config.semantic_Types[2] not in message_Result[index].field_types[f]:
                        continue

                # Answers that pass the check.
                validated_functions.append(func)
            
            field_Functions[f] = validated_functions
    
    
    return message_Result

def Validation(message_Result,payload_message):
    print("\n\n\n****************Start Corrector!!!*********************")

    msg_nums = len(payload_message)

    '''Clustering'''
    Command_field = Command_Exploration(message_Result,payload_message)

    if not Command_field:
        Command_field = config.defaultCommand



    print(f"Command_field:{Command_field}")


    Command_pos = int(Command_field.split(',')[0])
    Command_size = Command_field.count(',') + 1


    Clusters = Clustering(payload_message, msg_nums, Command_pos, Command_size)

    for i in range(msg_nums):
        if Command_field in message_Result[i].field_funcs:
            message_Result[i].field_funcs[Command_field] = ['Command']

    '''Type/Function Refinement'''

    for k, v in Clusters.items():
        '''Type Validation'''
        print(f"############# Cluster :{k} ")
        Type_Validation(Command_field, Command_size,message_Result, v)

        message_Result = Function_Validation(Command_field, Command_size,message_Result, v)

    for i in range(0,msg_nums):
        print(f"\n\n")
        print(f"payload_message: {message_Result[i].payload}")
        print(f"fields: {message_Result[i].fields}")
        print(f"boundaries: {message_Result[i].boundaries}")
        print(f"field_Types: {message_Result[i].field_types}")
        print(f"field_Functions: {message_Result[i].field_funcs}")
    
    return message_Result
    
