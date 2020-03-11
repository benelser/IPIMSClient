# The UNOFFICIAL (but useful) Python client for the Rapid7 Insight Platform
This code was thrown together to faciliate the dumping of asset information from the Insight Platform. This is not supported for production use by myself or Rapid7. 

## Requirements
This client is dependent on [Selenium Client Driver](https://www.selenium.dev/selenium/docs/api/py/) and makes use of the [geckodriver](https://github.com/mozilla/geckodriver). 

## Install
```bash
git clone https://github.com/benelser/IPIMSClient.git
cd IPIMSClient/
sudo python3 -m pip install -r requirements.txt
sudo python3 ipims_client.py 
````

## Directory
```bash
-rw-r--r-- 1 belser belser 1965 Mar 11 10:11 geckodriver.log
-rwxr-xr-x 1 belser belser 9481 Mar 11 10:07 ipims_client.py
-rw-r--r-- 1 belser belser  610 Mar 11 10:07 readme.md
-rw-r--r-- 1 belser belser   17 Mar 11 10:07 requirements.txt
```

## Checks 
Currently using sudo to download driver and then running script as sudo once creates log in current working directory. After the log is created. Can run the script w/o sudo like:
```bash
python3 ipims_client.py 
```
Ensure geckodriver.log is in the same directory as script and your current owner has permissions to it.
