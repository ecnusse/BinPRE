wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
tar -xzf pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
cd pin-3.28-98749-g6643ecee5-gcc-linux
sudo ln -s ${PWD}/pin /usr/local/bin
echo export PIN_ROOT=${PWD} >> ~/.bashrc
source ~/.bashrc