#!/bin/bash
sudo apt-get update -y && apt-get upgrade -y

# Install geckdriver
if which geckodriver; then echo "Driver installed"; else wget https://github.com/mozilla/geckodriver/releases/download/v0.26.0/geckodriver-v0.26.0-linux64.tar.gz -O /tmp/geckodriver.tar.gz && sudo tar -C /opt -xzf /tmp/geckodriver.tar.gz && sudo chmod 755 /opt/geckodriver && sudo ln -fs /opt/geckodriver /usr/bin/geckodriver && sudo ln -fs /opt/geckodriver /usr/local/bin/geckodriver; fi

# check for IPIMS_Client.py dependencies
if dpkg --list firefox; then echo "Firefox installed"; else sudo apt-get install firefox xvfb -y; fi
if dpkg --list python3-pip; then echo "python3-pip installed"; else sudo apt-get install python3-pip -y; fi
