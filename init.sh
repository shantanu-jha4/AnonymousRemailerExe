#!/bin/bash

sudo apt update
sudo apt install python3-pip
pip3 install pynacl --no-input
pip3 install protobuf --no-input
git clone https://github.com/shantanu-jha4/AnonymousRemailerExe.git -b remailer
cd AnonymousRemailerExe
rm remailer1_config.yaml remailer2_config.yaml remailer3_config.yaml data/remailer1.key data/remailer2.key data/remailer3.key
mv data/remailerx.key data/remailerz.key
