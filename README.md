# BinPRE
A protocol reverse engineering(PRE) tool that accurately and finely accomplished field inference for protocol messages.

## Directory Structure

```
BinPRE
   |
   |--- Analyzer:                       The source code of BinPRE
       |
       |--- fsend_split.py:                   The entry of BinPRE, which accepts the tool parameters
       |--- Separator.py:                     The main module of our Format Extraction
       |--- Speculator.py:                    The main module of our Semanic Inference
       |--- Corrector.py:                     The main module of our Semantic Refinement
       |
       |--- Baseline:  
          |
          |--- Polyglot     The modules of Polyglot
          |--- AutoFormat   The modules of AutoFormat
          |--- Tupni        The modules of Tupni

   |--- src:                            The Taint Tracker for monitoring server execution.
   |
   |--- BinPRE_Res:                     The the other three ExeT-based baselines.
       |
       |--- {protocol}_{msgnum} 
          |
          |--- {protocol}_{msgnum}_eval.txt      The results of BinPRE
          |--- {protocol}_{msgnum}_bo_eval.txt   The results of the other three ExeT-based baselines. 
```


## Installation Steps.

### preliminary request
Ubuntu 20.04

python3.8

#### Step 1 install **pin-3.28**：

```
./install_pin.sh

```
#### Step 2 install **BinPRE**:
```
cd ../pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/
git clone https://github.com/BinPRE/BinPRE
cd BinPRE
pip3 install -r requirements.txt
```

#### Step 3 download and install the object to be tested:
```
cd BinPRE/src
# install the server to be tested
```


## How to use BinPRE & re-implementations(Baselines: Polyglot, AutoFormat, Tupni)
(An example: freemodbus: https://github.com/cwalter-at/freemodbus)

The binary file of freemodbus is stored in ```./BinPRE/src/freemodbus/tcpmodbus``` 

**Note that**, by replacing packet captures (pcaps) and protocol implementations(binary files), you can easily start analyzing other protocols!

You can quickly try BinPRE with following steps:

step 1: instrument and start the server
```
# ==== Execution Monitor
cd ~/pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/BinPRE/src
./run compile taint
./run run taint ./freemodbus/tcpmodbus
#type 'e' to enable the protocol stack

```
step2a <u>(BinPRE)</u>: Simulate client sending messages and Reverse Engineering (BinPRE mode: 'oa')
```
# ==== Field Inference(Format & Semantic) & Evaluation

cd ~/pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/BinPRE/Analyzer
python3 fsend_split.py modbus 0 0 oa xx big 0 

<Please enter the value of threadId: 1> #For this example is '1'

```

step2b <u>(Baselines)</u>: Simulate client sending messages and Reverse Engineering (baselines mode: 'bo' )
```
# ==== Field Inference(Format & Semantic) & Evaluation

cd ~/pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/BinPRE/Analyzer
python3 fsend_split.py modbus 0 0 bo xx big 0 

<Please enter the value of threadId: 1> #For this example is '1'

```





