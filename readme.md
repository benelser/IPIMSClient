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

# Checks 
Ensure geckodriver.log is in the same directory as script and your current owner has permissions to it.
