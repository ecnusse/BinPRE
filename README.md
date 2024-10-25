# BinPRE
A protocol reverse engineering(PRE) tool that accurately and finely accomplished field inference for protocol messages.

## Directory Structure

```
BinPRE
   |--- Artifact_Evaluation:                  Enter into this folder for Artifact Evaluation
       |
       |--- BinPRE_scripts             A series of scripts used to run BinPRE.
       |--- ExeT-based_scripts         A series of scripts used to run Polyglot, AutoFormat, and Tupni.
       |--- Optional_install          (Optional) A series of scripts used to install all the server used in our experiments.
       |
   |--- Analyzer:                       The source code of BinPRE
       |
       |--- fsend_split.py:                   The entry of BinPRE, which accepts the tool parameters
       |--- Separator.py:                     The main module of our Format Extraction
       |--- Speculator.py:                    The main module of our Semanic Inference
       |--- Corrector.py:                     The main module of our Semantic Refinement
       |
       |--- Baseline:                   The re-implementations of the other three ExeT-based baselines.
          |
          |--- Polyglot     The modules of Polyglot
          |--- AutoFormat   The modules of AutoFormat
          |--- Tupni        The modules of Tupni

   |--- src:                            The Taint Tracker for monitoring server execution.
   |
   |--- BinPRE_Res:                     The folder of outputs.
       |
       |--- {protocol}_{msgnum} 
          |
          |--- {protocol}_{msgnum}_eval.txt      The results of BinPRE
          |--- {protocol}_{msgnum}_bo_eval.txt   The results of the other three ExeT-based baselines. 
```


## Running Environment.

We summarize the major setup instructions as follows:

### Prerequisite
Ubuntu 20.04

python3.8

### How to install

We provide the following two installation options for your consideration.
As some servers require a carefully configured environment, we recommend that you install BinPRE and the server under testing within a Docker container <u>(Method A. Install with Dockerfile)</u>. This approach helps ensure the server operates in an correct environment.

#### A. Install with Dockerfile (Recommend)

```
docker pull homebrew/ubuntu20.04
git clone https://github.com/ecnusse/BinPRE.git
cd BinPRE
docker build . -t binpre_ae
docker run -it --privileged binpre_ae /bin/bash
```
By default, the ```BinPRE/src``` directory contains a binary file that implements the Modbus protocol, which we provide. Additionally, users are supported to add instructions into the Dockerfile to install other protocol implementations. When you install using the Dockerfile, the implementations for all these protocols will be automatically installed in the ```~/BinPRE/src``` directory.

#### B. Manully install step-by-step

**BinPRE & requirements & pin-3.28,**：

```
cd ~
git clone https://github.com/BinPRE/BinPRE
cd BinPRE
./install_preliminary.sh
./install_pin.sh
cd ..
```
**(optional) download and install the object to be tested:**
```
cd BinPRE/src
# install the server to be tested
```
By default, the ```BinPRE/src``` directory contains a binary file that implements the Modbus protocol, which we provide.
If you would like to test implementations of other protocols, please install them in the ```BinPRE/src``` directory. Additionally, please place the corresponding PCAP files and Groundtruth files in the ```BinPRE/Analyzer/Groundtruth/``` and ```BinPRE/Analyzer/Groundtruth/``` directories, respectively. 



### Quick Start in the docker

**Use modbus as an Example**

#### Step1: start server (keep it running for interaction with BinPRE in step 2)
```
cd ~/BinPRE/Artifact_Evaluation/BinPRE_scripts
./run_modbus_server.sh
```
For testing this implementation of Modbus (server), <u>please type 'e' in the terminal</u> after starting the server to enable the protocol stack.

Note that, please keep the server running. BinPRE uses the execution information obtained from the interaction between the server and client to complete the analysis. Thus, when you run the following ```./run_<xx>_client.sh```, you need to make sure that ```./run_<xx>_server.sh``` is running as well.

#### Step2: run BinPRE

We would recommend that you open an additional terminal window. This will allow you to more intuitively experience the interaction between step 1 and step 2.

```
cd ~/BinPRE/Artifact_Evaluation/BinPRE_scripts
./run_modbus_client.sh
```
When BinPRE has sent 50 messages and started waiting for user interaction, <u>please enter '1' in the terminal</u> to provide BinPRE with the correct thread number to complete the analysis.

Note that,
1) The thread number may vary between different protocol implementations. Please check the required thread number in the scripts ```./run_<ProtocolName>_client.sh``` and make sure that you have entered the correct thread numbers for analysis.
2) We have provided references to the time cost of the tool using comments in ```./run_<xx>_client.sh```. Thus, if the runtime is significantly exceeded, it may be due to a runtime error.

#### Step3: check results

At the end of Step 2, a summary of the results is displayed on the terminal for direct viewing. 
Meanwhile, the results of BinPRE are stored in the ```~/BinPRE/BinPRE_Res/<ProtocolName>_50``` folder. Thus, for this running example, please check the results in the folder ```~/BinPRE/BinPRE_Res/modbus_50/```.


According to the Directory Map descibed above, please open the file ```~/BinPRE/BinPRE_Res/modbus_50/modbus_50_eval.txt ``` to check the following results:

```
cd ~/BinPRE/BinPRE_Res/modbus_50/
cat modbus_50_eval.txt
```

**RQ1: Format Extraction on modbus**
```
Evaluation Part For BinPRE---------------------------------
Average_Accr:0.9976615384615386
Average_Pre:0.9955555555555555
Average_Rec:1.0
F1_score:0.9977728285077951
Average_Perf:0.9942857142857143
```
The above results correspond to the evaluation data of BinPRE in Table 4 of the paper, demonstrating the effectiveness of BinPRE for Format Extraction on Modbus.

**RQ2 & 3: Semantic Inference (w/ and w/o Semantic Refinement) on modbus**

```
\Semantic-Type Evaluation Part For BinPRE(no validation)---------------------------------
no_Average_Pre:0.8386666666666666
no_Average_Rec:0.6161904761904765
no_F1_score:0.710418085013529
```
```
\Semantic-Type Evaluation Part For BinPRE(Validated)---------------------------------
Average_Pre:0.8313095238095235
Average_Rec:0.8463095238095234
F1_score:0.8387424644850842
```
```
\Semantic-Function Evaluation Part For BinPRE(no validation)---------------------------------
Average_Pre:0.43200000000000005
Average_Rec:0.87
F1_score:0.5773271889400923
```
```
\Semantic-Function Evaluation Part For BinPRE(Validated)---------------------------------
Average_Pre:0.763333333333333
Average_Rec:1.0
F1_score:0.8657844990548201
```
The above results correspond to the evaluation data of BinPRE in Table 6 of the paper, demonstrating the effectiveness of BinPRE for Semantic Type (Function) Inference w/o and w/ Semantic Refinement on Modbus.
Note that, 
1) ''no validation'' means Semantic Inference w/o Semantic Refinement, and ''Validated'' means Semantic Inference w/ Semantic Refinement. 
2) ''Semantic-Type'' and ''Semantic-Function'' means Semantic Inference on field types and functions, respectively.

As our reverse engineering process is conducted through monitoring and analyzing the runtime information of the servers, it is normal for a minor degree of variance to exist in the output data between each execution.


### (Optional) Run the three ExeT-based baselines

We also provide the scripts for running the three ExeT-based baselines: Polyglot, AutoFormat, and Tupni.

**Also, use modbus as an Example**

#### Step1: start server (keep it running for interaction with the baselines in step 2)
```
cd ~/BinPRE/Artifact_Evaluation/ExeT-based_scripts
./run_modbus_server.sh
```
For testing this implementation of Modbus (server), <u>please type 'e' in the terminal</u> after starting the server to enable the protocol stack.

Note that, please keep the server running. BinPRE uses the execution information obtained from the interaction between the server and client to complete the analysis. Thus, when you run the following ```./run_<xx>_client.sh```, you need to make sure that ```./run_<xx>_server.sh``` is running as well.

#### Step2: run the ExeT-based baselines

We would recommend that you open an additional terminal window. This will allow you to more intuitively experience the interaction between step 1 and step 2.

```
cd ~/BinPRE/Artifact_Evaluation/ExeT-based_scripts
./run_modbus_client.sh
```
When the Analyzer has sent 50 messages and started waiting for user interaction, <u>please enter '1' in the terminal</u> to provide the Analyzer with the correct thread number to complete the analysis.

Note that,
1) The thread number may vary between different protocol implementations. Please check the required thread number in the scripts ```./run_<ProtocolName>_client.sh``` and make sure that you have entered the correct thread numbers for analysis.
2) We have provided references to the time cost of the tool using comments in ```./run_<xx>_client.sh```. Thus, if the runtime is significantly exceeded, it may be due to a runtime error.

#### Step3: check results

According to the Directory Map descibed above, please open the file ```~/BinPRE/BinPRE_Res/modbus_50/modbus_50_bo_eval.txt ``` to check the following results:
```
cd ~/BinPRE/BinPRE_Res/modbus_50/
cat modbus_50_bo_eval.txt
```

**RQ1: Format Extraction on modbus**
```
Evaluation Part For Polyglot_Syntax---------------------------------
Average_Accr:0.9138487179487175
Average_Pre:0.8773535353535351
Average_Rec:1.0
F1_score:0.9346705549397926
Average_Perf:0.8403174603174602
******************

Evaluation Part For AutoFormat_Syntax---------------------------------
Average_Accr:0.9138487179487175
Average_Pre:0.8773535353535351
Average_Rec:1.0
F1_score:0.9346705549397926
Average_Perf:0.8403174603174602
******************

Evaluation Part For Tupni_Syntax---------------------------------
Average_Accr:0.8212858974358977
Average_Pre:0.7948857808857808
Average_Rec:1.0
F1_score:0.885722968392454
Average_Perf:0.6153492063492067
******************

```
The results correspond to the evaluation data of the three ExeT-based baselines (Polyglot, AutoFormat, and Tupni) in Table 4 of the paper, demonstrating their effectiveness for Format Extraction on Modbus.

As our reverse engineering process is conducted through monitoring and analyzing the runtime information of the servers, it is normal for a minor degree of variance to exist in the output data between each execution.


### (Optional) Introduction to parameters in the running scripts.

**Use modbus as an Example**

#### For the scripts (```./run_<ProtocolName>_server.sh```) in Step 1

```
./run run taint ./freemodbus/tcpmodbus
```

Here, 

```run```: specify the operation that needs to be done.

```taint```: specify the name of the shared object compiled by Pin. This file contains the logic of taint tracking, which is used to instrument the binary executable of the servers (protocol implementations) and print execution information.

```./freemodbus/tcpmodbus```: the start command of the server (protocol implementation) under testing. **Please replace it as needed**.

#### For the scripts (```./run_<ProtocolName>_client.sh```) in Step2

```
python3 fsend_split.py modbus 0 0 oa xx big 0
```

Here, （from left to right.）
```modbus```: specify the name of the protocol under testing.

```0(manual flag)```: specify whether the analyzer will be automatically running or not. We recommend that users keep this option.

```0(text flag)```: specify whether the protocol under testing contains text or not. '0' indicates the protocol is a binary protocol. '1' indicates the protocol is a text/mixed protocol. **Please replace it as needed**.

```oa```: sepecify the running mode of the Analyzer. 'oa' indicates that you are testing the server with BinPRE (our method). 'bo' indicates that you are testing the server with the ExeT-based baselines (Polyglot, AutoFormat, and Tupni). **Please replace it as needed**.

```xx```: specify the evaluation mode of the protocol under testing. 'xx' means the Groundtruth of the protocols is set based on the message types. 'index' means the Groundtruth of the protocols is set based on the message index. **Please replace it as needed**.

```big```: specify the endianness of the protocol under testing. 'little' means Little-endian and 'big' means Big-endian. **Please replace it as needed**.

```0```: specify whether the thread number could be ignored or not. '0' means the user needs to provide a correct thread number. '1' means it is not necessary for the user to provide a correct thread number. **Please replace it as needed**.

