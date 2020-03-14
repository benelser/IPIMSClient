from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy, ProxyType
import urllib.request
import sys
import time
from getpass import getpass
import ssl
import os
import requests
import json
from subprocess import Popen, PIPE, STDOUT
import shutil
import apt

requests.packages.urllib3.disable_warnings()

class obj(object):
            def __init__(self, d):
                for a, b in d.items():
                    if isinstance(b, (list, tuple)):
                        setattr(self, a, [obj(x) if isinstance(x, dict) else x for x in b])
                    else:
                        setattr(self, a, obj(b) if isinstance(b, dict) else b)

class platform_client:
    def __init__(self, username, password, organization):
        self.username = username
        self.password = password
        self.organization_id = ""
        self.session = requests.session()
        self.IPIMS_SESSION = ""
        self.organization_name = organization
        self.login()
        self.get_org_id()

    def login(self):
        os.system('clear')
        print("Bootstrapping Insight Platform Authentication")
        # Testing only ensure to set system proxy
        # proxy = Proxy({
        #     'proxyType': ProxyType.SYSTEM,

        # })
        # browser = webdriver.Firefox(proxy=proxy, options=browser_options)
        # Selenium bootstrap
        browser_options = webdriver.FirefoxOptions()
        browser_options.add_argument('-headless')
        browser = webdriver.Firefox(options=browser_options)
        browser.get("https://insight.rapid7.com/login")
        assert "Rapid7 - Login" in browser.title
        uname = browser.find_element_by_id("okta-signin-username")
        password = browser.find_element_by_id("okta-signin-password")
        uname.send_keys(self.username)
        password.send_keys(self.password)
        submit = browser.find_element_by_id("okta-signin-submit")
        submit.submit()

        # Loop while page loads 
        seconds = 0
        loaded = False
        while loaded == False:
            if seconds == 30:
                loaded = True
            try:
                current_url = browser.current_url
                if current_url == 'https://insight.rapid7.com/platform#/':
                    loaded = True
                    break
                else:
                    os.system('clear')
                    print("Bootstrapping Insight Platform Authentication")
                    time.sleep(5)
                    seconds += 5
                    continue
            except:
                    os.system('clear')
                    print("Bootstrapping Insight Platform Authentication")
                    time.sleep(5)
                    seconds += 5
                    continue
        
        try:
            cookies  = browser.get_cookies()
            IPIMS_SESSION = f"IPIMS_SESSION={cookies[5]['value']};"
            self.IPIMS_SESSION = IPIMS_SESSION
        except:
            os.system('clear')
            os.sys.exit("Unable to authenticate to the Insight Platform\nEnsure the email and password are correct.")

    def get_org_id(self):
        # this org id is acutally the customer level org id...
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Host': 'insight.rapid7.com',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cookie': self.IPIMS_SESSION
        }
        self.session.headers.clear()
        self.session.headers.update(headers)
        try:
            r = self.session.get('https://insight.rapid7.com/api/1/user/customers', verify=False, allow_redirects=True)
            responseBody = json.loads(r.content)
            orgs = responseBody[0]['organizationAccessList']
            if len(orgs) > 1:
                for org in orgs:
                    if org['organizationName'].upper() == self.organization_name.upper():
                        self.organization_id = org['organizationId']
                        return
            else:
                self.organization_id = orgs[0]['organizationId']
                return
        except:
            self.organization_id = False
        self.organization_id = False

    def __str__(self):
        return f'organization_id: {self.organization_id}\norganization_name: {self.organization_name}\nIPIMS_SESSION: {self.IPIMS_SESSION}\n '

    def get_asset_list(self):
        headers = {
            'Host': 'us.query.datacollection.insight.rapid7.com',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'content-type': 'application/json',
            'R7-Organization-Id': self.organization_id,
            'R7-Consumer': 'platform-data-collection-management',
            'Origin': 'https://insight.rapid7.com',
            'Connection': 'close',
            'Cookie': self.IPIMS_SESSION 
        }
        self.session.headers.clear()
        self.session.headers.update(headers)
        # Drops first 10000 assets for env with < 10000 assets cursor pagination is required 
        query = {
            "operationName":"GetFirstOrganizationAsset",
            "variables":{
                "orgId":self.organization_id
            },
            "query":"query GetFirstOrganizationAsset($orgId: String!, $after: String) {\n  organization(id: $orgId) {\n    __typename\n    assets(first: 10000, after: $after, filter: {components: INSIGHT_AGENT}) {\n      edges {\n        __typename\n        node {\n          ...Asset\n          __typename\n        }\n        cursor\n      }\n      pageInfo {\n        startCursor\n        endCursor\n        __typename\n      }\n      totalCount\n      __typename\n    }\n  }\n}\n\nfragment Asset on Asset {\n  id\n  agent {\n    id\n    agentMode\n    agentVersion\n    agentSemanticVersion\n    agentStatus\n    agentLastUpdateTime\n    timestamp\n    collector {\n      name\n      __typename\n    }\n    agentJobs {\n      executedJobs(filter: {events: [FAILED, ERROR]}) {\n        event\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  location {\n    city\n    countryCode\n    countryName\n    region\n    __typename\n  }\n  host {\n    hostNames {\n      name\n      source\n      __typename\n    }\n    primaryAddress {\n      ip\n      mac\n      __typename\n    }\n    alternateAddresses {\n      ip\n      mac\n      __typename\n    }\n    description\n    __typename\n  }\n  orgId\n  publicIpAddress\n  platform\n  lastBootTime\n  lastLoggedInUser\n  __typename\n}\n"
        }
        jsondata = json.dumps(query)
        jsondataasbytes = jsondata.encode('utf-8') 
        try:
            r = self.session.post('https://us.query.datacollection.insight.rapid7.com/v1/guardian/graphql', data=jsondataasbytes, verify=False, allow_redirects=True)
            responseBody = json.loads(r.content)
            hosts = []
            nodes = responseBody['data']['organization']['assets']['edges']
            for node in nodes:
                hosts.append(obj(node['node']))

            return hosts
        except:
            return False

def check_environment():
    os.system('clear')
    print("Checking to see if dependencies are met")
    cache = apt.Cache()
    try:
        if cache['python3-pip'].is_installed and cache['firefox'].is_installed or shutil.which("firefox") and shutil.which("geckodriver"):
            print("All installed")
    except :
        os.system('clear')
        print("Attempting to install bootstrap shell script")
        install_bootstrap()

def install_bootstrap():
    cmd = 'sudo wget https://raw.githubusercontent.com/benelser/AWSBOTOQuickStart/master/InsightIDR/bootstrap.sh -O bootstrap.sh && chmod 755 ./bootstrap.sh && ./bootstrap.sh'
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    output = p.stdout.read()
    cache = apt.Cache()
    try:
        if cache['python3-pip'].is_installed and cache['firefox'].is_installed and shutil.which("geckodriver"):
            print("Dependencies met")
    except:
        os.system('clear')
        os.sys.exit(f"Failed to install dependencies.\nTry manually running {cmd}")

def get_user_input(selection):
    if selection == 1:
        answer = "n"
        while answer != 'y':
            os.system("clear")
            org = input("Enter Rapid7 Insight Platform Organization Name:\n")
            answer = input(f"Is {org} correct y/n\n")
        return org
    if selection == 2:
        answer = "n"
        while answer != 'y':
            os.system("clear")
            email = input("Enter Rapid7 Insight Platform email:\n")
            answer = input(f"Is {email} correct y/n\n")
        return email
    if selection == 3:
        os.system("clear")
        return getpass("Enter Rapid7 Insight Platform password:\n")
     
def main():
    check_environment()
    organization = get_user_input(1)
    email = get_user_input(2)
    password = get_user_input(3)
    client = platform_client(email, password, organization)
    print(client)
    hosts = client.get_asset_list()
    print(f"Total platform connected assets: {len(hosts)}")
    for host in hosts:
        print(f"Status: {host.agent.agentStatus}\tplatform: {host.platform}\tId: {host.id}\tplatform: {host.platform}\thostname: {host.host.hostNames[0].name}\tagentVersion: {host.agent.agentSemanticVersion}")

main()