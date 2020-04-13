#!/bin/bash

sudo apt-get install python3.7
sudo apt-get install python3-distutils
curl -O https://bootstrap.pypa.io/get-pip.py
python3 get-pip.py --user
echo "export PATH=~/.local/bin:$PATH" >> ~/.bashrc
source ~/.bashrc
pip3 install pynacl --no-input
pip3 install protobuf --no-input
