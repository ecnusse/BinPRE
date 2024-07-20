
semantic_Types = ['Static', 'Group', 'String', 'Bit Field', 'Bytes']
semantic_Functions = ['Command', 'Length', 'Delim', 'CheckSum', 'Aligned', 'Filename']


modbus_Syntax_Groundtruth = {}

#format1
modbus_Syntax_Groundtruth[b'\x01'] = [-1,1,3,5,6,7,9]
modbus_Syntax_Groundtruth[b'\x02'] = [-1,1,3,5,6,7,9]
modbus_Syntax_Groundtruth[b'\x03'] = [-1,1,3,5,6,7,9]
modbus_Syntax_Groundtruth[b'\x04'] = [-1,1,3,5,6,7,9]
modbus_Syntax_Groundtruth[b'\x05'] = [-1,1,3,5,6,7,9]
modbus_Syntax_Groundtruth[b'\x06'] = [-1,1,3,5,6,7,9]
#format2
modbus_Syntax_Groundtruth[b'\x0f'] = [-1,1,3,5,6,7,9,11,12]
modbus_Syntax_Groundtruth[b'\x10'] = [-1,1,3,5,6,7,9,11,12]
#format3
modbus_Syntax_Groundtruth[b'\x0f'] = [-1,1,3,5,6,7,9,11,12]
modbus_Syntax_Groundtruth[b'\x10'] = [-1,1,3,5,6,7,9,11,12]


#Groundtruth: based on protocol specifications + Wireshark

modbus_Semantic_Groundtruth = {}

modbus_Semantic_Functions_Groundtruth = {}

modbus_lengthOffset = '4,5'

modbus_commandOffset = '7'

''' Semantic-Type Groudtruth'''

#format1
modbus_Semantic_Groundtruth[b'\x01'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[3],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3]
    }
modbus_Semantic_Groundtruth[b'\x02'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[3],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3]
    }
modbus_Semantic_Groundtruth[b'\x03'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[3],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3]
    }
modbus_Semantic_Groundtruth[b'\x04'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[3],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3]
    }
modbus_Semantic_Groundtruth[b'\x05'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[3],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3]
    }
modbus_Semantic_Groundtruth[b'\x06'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[3],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3]
    }

#format2
modbus_Semantic_Groundtruth[b'\x0f'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[0],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3],
    '12':semantic_Types[3],
    '13,+':semantic_Types[4]
    }   
modbus_Semantic_Groundtruth[b'\x10'] = {
    '0,1':semantic_Types[3],
    '2,3':semantic_Types[0],
    '4,5':semantic_Types[0],
    '6':semantic_Types[0],
    '7':semantic_Types[1],
    '8,9':semantic_Types[3],
    '10,11':semantic_Types[3],
    '12':semantic_Types[3],
    '13,+':semantic_Types[4]
    }


''' Semantic-Function Groudtruth'''
modbus_Semantic_Functions_Groundtruth[b'\x01'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}

modbus_Semantic_Functions_Groundtruth[b'\x02'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}


modbus_Semantic_Functions_Groundtruth[b'\x03'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}

modbus_Semantic_Functions_Groundtruth[b'\x04'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}

modbus_Semantic_Functions_Groundtruth[b'\x05'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}
modbus_Semantic_Functions_Groundtruth[b'\x06'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}

modbus_Semantic_Functions_Groundtruth[b'\x0f'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}

modbus_Semantic_Functions_Groundtruth[b'\x10'] = {
    '4,5':semantic_Functions[1],
    '7':semantic_Functions[0],
}