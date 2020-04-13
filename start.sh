#!/bin/bash

apt install python3-pip
pip3 install protobuf --no-input
pip3 install pynacl --no-input
cd /home/ubuntu/AnonymousRemailerExe/
nohup python3 remailer.py 30999 --ts "15.223.94.116 22300" &
