FROM homebrew/ubuntu20.04


# install BinPRE

RUN cd ~ && \
    git clone https://github.com/BinPRE/BinPRE && \
    cd BinPRE && \
    git checkout Artifact_Evaluation && \
    sudo chmod 777 -R ./ && \
    ./install_preliminary.sh

# install pin (./install_pin.sh)

RUN cd ~/BinPRE && \
    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz && \
    tar -xzf pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz && \
    chmod 777 -R ./ && \
    cd pin-3.28-98749-g6643ecee5-gcc-linux && \
    sudo ln -s ${PWD}/pin /usr/local/bin 


# PUT(example): Modbus

# (optional) please add addtional instructions to install other  servers


RUN sudo chmod 777 -R ~/BinPRE/



