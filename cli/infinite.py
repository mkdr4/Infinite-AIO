# -*- coding: utf-8 -*-
try:
    from solana.rpc.commitment import Confirmed
    from solana.transaction import Transaction, SIG_LENGTH, TransactionInstruction, AccountMeta
    from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
    from solana.system_program import SYS_PROGRAM_ID
    from solana.sysvar import SYSVAR_RENT_PUBKEY
    from solana.publickey import PublicKey
    from solana.rpc.types import TxOpts
    from solana.message import Message as SolanaMessage
    from solana.keypair import Keypair
    from solana.rpc.api import Client
    from dhooks_lite import Webhook, Embed, Footer, Image, Thumbnail, Author, Field
    from python3_anticaptcha import HCaptchaTaskProxyless, GeeTestTaskProxyless, AntiCaptchaControl
    from selenium.webdriver.chrome.options import Options
    from requests.sessions import dispatch_hook, session
    from fake_useragent import UserAgent
    from progress.spinner import Spinner
    from seleniumwire import webdriver
    from datetime import datetime, timedelta, date
    from pypresence import Presence
    from colorama.ansi import Fore
    from colorama import init, Style
    from tabulate import tabulate
    from hashlib import sha256
    from tkinter import *
    from enum import Enum
    import os, platform, subprocess, re, sys, glob
    import chromedriver_autoinstaller
    import multiprocessing as mp
    import urllib.parse
    import webbrowser
    import threading
    import requests
    import logging
    import urllib3
    import tkinter
    import asyncio
    import random
    import string
    import shutil
    import base64
    import base58
    import httpx
    import time
    import json
    import uuid
    import gzip
    import math

# DISCORD
    class Discord:
        def __init__(self):
            self.session = requests.Session()
            self.headers = self.get_headers()
            
        def get_headers(self):
            ua = UserAgent()
            os = ['Mac OS X', 'Windows']
            random.shuffle(os)
            build_number = ['110451', '72112', '112296']
            random.shuffle(build_number)
            
            if os[0] == 'Mac OS X':
                mac_versions = ['12.1', '11.6.2', '10.15.7', '10.14.6', '10.13.6', '10.12.6', '10.11.6']
                random.shuffle(mac_versions)
                os_version = mac_versions[0]
                sec_ch_ua_platform = 'macOS'
            else:
                windows_versions = ['7', '10', '11']
                random.shuffle(windows_versions)
                os_version = windows_versions[0]
                sec_ch_ua_platform = 'Windows'
            
            user_agent = ua.chrome
            
            x_super_properties_random = json.dumps({
                "os":os[0],
                "browser":"Chrome",
                "device":"",
                "system_locale":"ru-RU",
                "browser_user_agent": user_agent,
                "os_version":os_version,
                "referrer":"",
                "referring_domain":"",
                "referrer_current":"",
                "referring_domain_current":"",
                "release_channel":"stable",
                "client_build_number":build_number[0],
                "client_event_source":None
            })
            
            return {
                'authority': 'discord.com',
                'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="97", "Chromium";v="97"',
                'x-super-properties': base64.b64encode(x_super_properties_random.encode("UTF-8")).decode("utf-8"),
                'x-context-properties': 'eyJsb2NhdGlvbiI6Ikludml0ZSBCdXR0b24gRW1iZWQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6bnVsbCwibG9jYXRpb25fY2hhbm5lbF9pZCI6IjkyNzY2MDYwMDM1MDM0NzI3NCIsImxvY2F0aW9uX2NoYW5uZWxfdHlwZSI6MSwibG9jYXRpb25fbWVzc2FnZV9pZCI6IjkzMDM2NTA5MjE0NTU1MzQwOCJ9',
                'x-debug-options': 'bugReporterEnabled',
                'sec-ch-ua-mobile': '?0',
                'content-type': 'application/json',
                'user-agent': user_agent,
                'x-discord-locale': 'ru',
                'sec-ch-ua-platform': '"'+sec_ch_ua_platform+'"',
                'accept': '*/*',
                'origin': 'https://discord.com',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
                'cookie': '__dcfduid=3fe72e30119411ec8cc91ba2df817907; __sdcfduid=3fe72e31119411ec8cc91ba2df817907ecd60e1dc612c92d9811f0f42ab350dc72e79edb5b9ef4d5dd902f9b49e99ac3; _gcl_au=1.1.1165806394.1636133392; _ga=GA1.2.1210318857.1636133392; _gid=GA1.2.1745247781.1641716216; locale=ru; OptanonConsent=isIABGlobal=false&datestamp=Tue+Jan+11+2022+08%3A55%3A35+GMT%2B0500+(%D0%95%D0%BA%D0%B0%D1%82%D0%B5%D1%80%D0%B8%D0%BD%D0%B1%D1%83%D1%80%D0%B3%2C+%D1%81%D1%82%D0%B0%D0%BD%D0%B4%D0%B0%D1%80%D1%82%D0%BD%D0%BE%D0%B5+%D0%B2%D1%80%D0%B5%D0%BC%D1%8F)&version=6.17.0&hosts=&landingPath=NotLandingPage&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1&AwaitingReconsent=false',
            }

        def get_user(self, token, proxy):
            try:
                self.headers['authorization'] = token
                r = requests.get('https://discord.com/api/v6/users/@me', headers=self.headers, proxies={'http':'http://'+proxy}).json()
                self.user_name = r['username']
                self.user_id = r['id']
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--get_user-->')
                return 'Error get user'
            
            return self.user_name

        def get_count_messages(self, token, proxy, server):
            if self.get_user(token, proxy) == 'Error get user':
                return 'Error', 'Error'          
            params = {
                'author_id': str(self.user_id),
            }
            
            response = requests.get('https://discord.com/api/v9/guilds/'+server+'/messages/search', params=params, headers=self.headers, proxies={'http':'http'+proxy})

            try:
                return self.user_name, str(response.json()['total_results'])
            except:
                return self.user_name, '-'

    class DsHook:
        def me(self, product, price, proxylist, checkoutTime, tx, api):
            self.fields = [
                Field('Product', str(product), inline=False),
                Field('Mint price', str(price[0]) + ' SOL'),
                Field('Task price', str(price[1]) + ' SOL'),
                Field('Proxylist', '||' + str(proxylist) + '||', inline=False),
                Field('Checkout time', str(str(checkoutTime) + ' ms'), inline=False),
                Field('Transaction', '[Solscan](https://solscan.io/tx/%s)'%tx, inline=False),
            ]
            self.image = 'http://cdn.shopify.com/s/files/1/0618/8384/2786/files/100x100.png?v=1639837250'
            self.private(api)
            self.fields = [
                Field('Product', str(product), inline=False),
                Field('Mint price', str(price[0]) + ' SOL'),
                Field('Task price', str(price[1]) + ' SOL'),
                Field('Checkout time', str(str(checkoutTime) + ' ms'), inline=False),
            ]
            self.public()
        def fff(self, product, price, tx, api):
            self.fields = [
                Field('Product', str(product), inline=False),
                Field('Price', str(price[0]) + ' SOL'),
                Field('Transaction', '[Solscan](https://solscan.io/tx/%s)'%tx, inline=False),
            ]
            self.image = 'http://cdn.shopify.com/s/files/1/0618/8384/2786/files/100x100.png?v=1639837250'
            self.private(api)
            self.fields = [
                Field('Product', str(product), inline=False),
                Field('Price', str(price[0]) + ' SOL'),
            ]
            self.public()
        def veve(self, task, number, proxy, time, pid, api):
            self.fields = [
                Field('Task:', '||' + str(task) + '||', inline=False),
                Field('Number:', str(number), inline=False),
                Field('Proxy:', '||' + str(proxy) + '||', inline=False),
                Field('Time:', str(time), inline=False),
                Field('Pid:', str(pid), inline=False),
            ]
            self.image = 'https://omi.veve.me/images/veve-logo.png'
            self.private(api)
            self.fields = [
                Field('Number:', str(number), inline=False),
                Field('Time:', str(time), inline=False),
                Field('Pid:', str(pid), inline=False),
            ]
            self.public()
        def bybit(self, product, price, task, proxy, time, pid, api):
            self.fields = [
                Field('Product:', str(product), inline=False),
                Field('Price:', str(price), inline=False),
                Field('Task:', str(task), inline=False),
                Field('Proxy:', '||' + str(proxy) + '||', inline=False),
                Field('Time:', str(time), inline=False),
                Field('Pid:', str(pid), inline=False),
            ]
            self.image = 'https://media.discordapp.net/attachments/951542924401836082/963735116281167882/Bybit.png'
            self.private(api)
            self.fields = [
                Field('Product:', str(product), inline=False),
                Field('Price:', str(price), inline=False),
                Field('Pid:', str(pid), inline=False),
            ]
            self.public()
        def private(self, api):
            hook = Webhook(api)
            e1 = Embed(
                title='Successfully checked out!',
                color=0x643395,
                timestamp=datetime.utcnow(),
                footer=Footer(
                    'Infinite AIO',
                    'https://media.discordapp.net/attachments/967039935058165800/974392751279976528/infinite1-1.png'
                ),
                thumbnail=Thumbnail(self.image),
                fields=self.fields
            )
            hook.execute(
                username='Infinite',
                avatar_url='https://media.discordapp.net/attachments/967039935058165800/974392751279976528/infinite1-1.png',
                embeds=[e1],
            )
        def public(self):
            list_hook = []
            hook = Webhook('https://discord.com/api/webhooks/' + str(list_hook[random.randint(0, 9)]))
            time.sleep(random.randint(0,20))
            e1 = Embed(
                title='Successfully checked out!',
                color=0xFF6F00,
                timestamp=datetime.utcnow(),
                footer=Footer(
                    'Infinite AIO',
                    'https://sun9-65.userapi.com/impg/fWEywPW6J9wp_tMBczbSlwh3rOckFDU3QIQ8aw/FsqlMshon84.jpg?size=630x630&quality=96&sign=6b3a9e8a60a5152c98520aff4e4dc6e5&type=album'
                ),
                thumbnail=Thumbnail(self.image),
                fields=self.fields
            )
            hook.execute(
                username='Infinite',
                avatar_url='https://sun9-65.userapi.com/impg/fWEywPW6J9wp_tMBczbSlwh3rOckFDU3QIQ8aw/FsqlMshon84.jpg?size=630x630&quality=96&sign=6b3a9e8a60a5152c98520aff4e4dc6e5&type=album',
                embeds=[e1],
            )

# FFF
    class FFFW3:

        def __init__(self):
            self.FFF_PROGRAM_ID = PublicKey('8BYmYs3zsBhftNELJdiKsCN2WyCBbrTwXd6WG4AFPr6n')
            self.FFF_COMMISSION_ADDRESS = PublicKey('2x3yujqB7LCMdCxV7fiZxPZStNy7RTYqWLSvnqtqjHR6')
            self.FFF_TOKEN_ADDRESS = PublicKey('FoXyMu5xwXre7zEoSvzViRk3nGawHUp9kUh97y2NDhcq')
            self.wire = False
            self.seller = None
            self.token_wallet = None

        def create_transaction(self, message):
            message = SolanaMessage.deserialize(bytes(message['tx']['data']))
            signatures = [base58.b58encode(bytes([1] * SIG_LENGTH))]
            self.transaction = Transaction.populate(
                message,
                signatures
            )

        def send_transaction(self, connection, transaction, signer):
            transaction.sign(signer)
            wire_txn = base64.b64encode(transaction.serialize()).decode('utf8')
            if self.wire is False:
                self.wire = True
                logging.getLogger('FFFSniper').info('Send transaction - [WireTxn: %s]' % (wire_txn))
            rpc_response = connection.send_transaction(
                transaction,
                signer,
                opts = TxOpts(
                    skip_confirmation = False,
                    preflight_commitment = Confirmed
                )
            )
            return rpc_response

        def get_signatures(
                self, connection,
                proxy, current_signatures = [],
                proxies = {}):
            while True:
                try:
                    json = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getSignaturesForAddress",
                        "params": [
                            "8BYmYs3zsBhftNELJdiKsCN2WyCBbrTwXd6WG4AFPr6n",
                            {
                                "limit": 50,
                                "commitment": "confirmed"
                            }
                        ]
                    }
                    if proxy is not None:
                        proxy_data = proxy.split(':')
                        proxies = {
                            'http' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                            'https' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                        }
                    try:
                        signatures = requests.post(
                            connection,
                            json = json,
                            proxies = proxies
                        ).json()['result']
                    except requests.exceptions.ProxyError as err:
                        logging.getLogger('FFFSniper').info('Get signatures - [Error: Proxy; Server: %s]' % (proxy))
                    for i in range(len(signatures)):
                        current_signatures.append(signatures[i]['signature'])
                    return set(current_signatures)
                except Exception as e:
                    logging.getLogger('FFFSniper').info('Get signatures - [Error: %s]' % (str(e)))

        def create_instruction(
                self, count,
                token_wallet, buyer, seller,
                buyer_foxy_acc, seller_foxy_acc,
                buyer_token_acc, token_wallet_acc):
            if self.decimals == 0:
                data = [80, 82, 193, 201, 216, 27, 70, 184, count, 0, 0, 0, 0, 0, 0, 0, 16, 39, 0, 0, 0, 0, 0, 0]
            else:
                data = [80, 82, 193, 201, 216, 27, 70, 184, count, 0, 0, 0, 0, 0, 0, 0, 32, 78, 0, 0, 0, 0, 0, 0]
            instruction = TransactionInstruction(
                keys=[
                    AccountMeta(pubkey=token_wallet, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=buyer, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=seller, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=self.token_address, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=self.FFF_COMMISSION_ADDRESS, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=self.FFF_COMMISSION_ADDRESS, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=token_wallet_acc, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=buyer_token_acc, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=self.FFF_TOKEN_ADDRESS, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=seller_foxy_acc, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=buyer_foxy_acc, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
                ],
                program_id = self.FFF_PROGRAM_ID,
                data = bytes(data)
            )
            return instruction

        def get_associated_accs(self, buyer, seller, token_wallet):
            buyer_token_acc = PublicKey.find_program_address(
                seeds=[
                    bytes(buyer),
                    bytes(TOKEN_PROGRAM_ID),
                    bytes(PublicKey(self.token_address))
                ], program_id=ASSOCIATED_TOKEN_PROGRAM_ID
            )[0]
            buyer_foxy_acc = PublicKey.find_program_address(
                seeds=[
                    bytes(buyer),
                    bytes(TOKEN_PROGRAM_ID),
                    bytes(self.FFF_TOKEN_ADDRESS)
                ], program_id=ASSOCIATED_TOKEN_PROGRAM_ID
            )[0]
            seller_foxy_acc = PublicKey.find_program_address(
                seeds=[
                    bytes(seller),
                    bytes(TOKEN_PROGRAM_ID),
                    bytes(self.FFF_TOKEN_ADDRESS)
                ], program_id=ASSOCIATED_TOKEN_PROGRAM_ID
            )[0]
            token_wallet_acc = PublicKey.find_program_address(
                seeds=[
                    bytes(token_wallet),
                    bytes(TOKEN_PROGRAM_ID),
                    bytes(PublicKey(self.token_address))
                ], program_id=ASSOCIATED_TOKEN_PROGRAM_ID
            )[0]
            return AssociatedTokenAccounts(
                buyer_foxy_acc, seller_foxy_acc,
                buyer_token_acc, token_wallet_acc
            )

        @staticmethod
        def create_keypair(b58_key):
            keypair = Keypair.from_secret_key(base58.b58decode(b58_key))
            return keypair

    class FFFBot(FFFW3):

        def __init__(self, phantom_key, rpc, proxies, params, token_address, taskid):
            super().__init__()
            self.keypair = FFFW3.create_keypair(
                phantom_key
            )
            self.taskid = taskid
            self.rpc = rpc
            self.proxies = proxies
            self.params = params
            self.token_address = token_address
            self.logged_tokens = {
                "listing": [],
                "checkout": [],
                "c_monitor": False,
                "m_monitor": False
            }
            self.listed_items = []
            self.rpc_response = None
            self.success = None
            self.price_success = None

        def market_monitor(self, proxy, m_monitor_log = False):
            while True:
                try:
                    if self.success is True:
                        return
                    headers = {
                        'referer': 'https://famousfoxes.com/',
                    }
                    proxy_data = proxy.split(':')
                    proxies = {
                        'http' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                        'https' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                    }
                    try:
                        response = requests.get(
                            'https://dens.famousfoxes.com/cache.json',
                            headers = headers,
                            proxies = proxies,
                            timeout = None
                        ).json()
                    except requests.exceptions.ProxyError as err:
                        logging.getLogger('FFFSniper').info('Market monitor - [Error: Proxy; Server: %s]' % (proxy))
                    if self.logged_tokens['m_monitor'] is not True:
                        self.logged_tokens['m_monitor'] = True
                        logging.getLogger('FFFSniper').info('Market monitor - [Status: started]')
                    if len(response) != 0:
                        if 'mint' in response[0]:
                            self.listed_items = response             
                except Exception as e:
                    logging.getLogger('FFFSniper').info('Market monitor data - [Error: %s]' % (str(e)))
                    return None

        def parse_token(self, seller, token_wallet, decimals, roof, price = None):
                for i in range(10**10):
                    time.sleep(0.001)
                    if self.success is True:
                        return
                    for listing in self.listed_items:
                        if listing['owner'] == seller and listing['mint'] == self.token_address:
                            self.decimals = decimals
                            price = listing['cost']
                    if price is None:
                        continue
                    if price <= roof:
                        if token_wallet not in self.logged_tokens['checkout']:
                            self.logged_tokens['checkout'].append(token_wallet)
                            logging.getLogger('FFFSniper').info('Checkouting - [Price: %s]' % (price))
                        self.seller = seller
                        self.token_wallet = token_wallet
                        self.price_success = str(price)
                        return None

        def check_transaction(
                self, signature,
                connection, proxy,
                proxies = {}):
            json = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [
                    signature,
                    "json"
                ]
            }
            if proxy is not None:
                proxy_data = proxy.split(':')
                proxies = {
                    'http' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                    'https' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                }
            for i in range(100):
                if self.success is True:
                    return
                try:
                    transaction = requests.post(
                        connection,
                        json = json,
                        proxies = proxies
                    ).json()
                except requests.exceptions.ProxyError as err:
                    logging.getLogger('FFFSniper').info('Check transaction - [Error: Proxy; Server: %s]' % (proxy))
                if transaction.get('result') is not None:
                    break
            if transaction.get('result') is None:
                    logging.getLogger('FFFSniper').info('Transaction is None')
            if transaction.get('result').get('meta') is not None:
                if 'err' in transaction['result']['meta']:
                    if transaction['result']['meta']['err'] is None:
                        if transaction['result']['meta'].get('postTokenBalances') is not None\
                        and len(transaction['result']['meta']['postTokenBalances']) != 0:
                            mint = transaction['result']['meta']['postTokenBalances'][0]['mint']
                            decimals = transaction['result']['meta']['postTokenBalances'][0]['uiTokenAmount']['decimals']
                            seller = transaction['result']['transaction']['message']['accountKeys'][0]
                            token_wallet = transaction['result']['transaction']['message']['accountKeys'][1]
                            if token_wallet not in self.logged_tokens['listing']:
                                self.logged_tokens['listing'].append(token_wallet)
                                logging.getLogger('FFFSniper').info('New listing - [Mint: %s]' % (mint))
                            if mint == self.token_address:
                                threading.Thread(
                                    target = self.parse_token,
                                    args = (
                                        seller,
                                        token_wallet,
                                        decimals,
                                        self.params['roof'],
                                    )
                                ).start()

        def parse_recent(self, connection, proxy_index = 0):
            current_signatures = self.get_signatures(connection, self.proxies[proxy_index])
            while True:
                if self.success is True:
                    return
                try:
                    if proxy_index >= len(self.proxies):
                            proxy_index = 0
                    signatures = self.get_signatures(
                        connection,
                        self.proxies[proxy_index]
                    )
                    new_signatures = set(signatures) - current_signatures
                    current_signatures |= new_signatures
                    proxy_index += 1
                    if self.logged_tokens['c_monitor'] is not True:
                        self.logged_tokens['c_monitor']  = True
                        logging.getLogger('FFFSniper').info('Contract monitor - [Status: started]')
                    for signature in list(new_signatures):
                        if proxy_index >= len(self.proxies):
                            proxy_index = 0
                        threading.Thread(
                            target = self.check_transaction,
                            args = (
                                signature,
                                connection,
                                self.proxies[proxy_index],
                            )
                        ).start()
                        proxy_index += 1
                        time.sleep(self.params['delay'])
                except Exception as e:
                    logging.getLogger('FFFSniper').info('Parse recent- [Error: %s]' % (str(e)))

        def parser_threads(self):
            for i in range(len(self.rpc)):
                for s in range(self.params['threads']):
                    threading.Thread(
                        target = self.parse_recent,
                        args = (
                            self.rpc[i],
                        )
                    ).start()
                    time.sleep(0.25)

        def market_threads(self):
            for proxy in self.proxies:
                threading.Thread(
                    target = self.market_monitor,
                    args = (proxy,)
                ).start()
                time.sleep(0.5)

        def transaction_thread(self, connection):
            try:
                seller = self.seller
                token_wallet = self.token_wallet
                associated_accs = self.get_associated_accs(
                    self.keypair.public_key,
                    PublicKey(seller),
                    PublicKey(token_wallet)
                )
                instruction = self.create_instruction(
                    self.params['count'],
                    PublicKey(token_wallet), PublicKey(self.keypair.public_key), PublicKey(seller),
                    PublicKey(associated_accs.buyer_foxy_acc), PublicKey(associated_accs.seller_foxy_acc),
                    PublicKey(associated_accs.buyer_token_acc), PublicKey(associated_accs.token_wallet_acc)
                )
                recent_blockhash = connection.get_recent_blockhash()['result']['value']['blockhash']
                transaction = Transaction(
                    fee_payer = self.keypair.public_key,
                    recent_blockhash = recent_blockhash
                )
                transaction.add(instruction)
                self.rpc_response = self.send_transaction(
                    connection,
                    transaction,
                    self.keypair,
                )
            except Exception as e:
                self.rpc_response = {'result': {'value': {'err': 'Error'}}}
                logging.getLogger('FFFSniper').info('Trasaction thread - [Error: %s]' % (str(e)))         

        def sniper_threads(self, old_seller = None):
            self.parser_threads()
            self.market_threads()
            while True:
                if Bot.localTasks[self.taskid]['status'] == 'STOP':
                    Bot.localTasks.pop(self.taskid)
                    self.success = True
                    return
                if self.seller != old_seller:
                    old_seller = self.seller
                    self.rpc_response = None  
                    for count, proxy in enumerate(self.proxies):
                        if count == 5:
                            break
                        for rpc in self.rpc:
                            threading.Thread(
                                target = self.transaction_thread,
                                args = (
                                    Client(rpc, commitment = Confirmed),
                                )
                            ).start()
                    while True:
                        if self.rpc_response is not None:
                            break
                    try:
                        if type(self.rpc_response.get('result')) is str:
                            self.success = True
                            return self.rpc_responses, self.price_success
                        self.rpc_response = None  
                    except Exception as e:
                        self.rpc_response = None  
                        logging.getLogger('FFFSniper').info('Sniper threads - [%s]' % (str(e)))

    class AssociatedTokenAccounts:

        def __init__(
                self,
                buyer_foxy_acc, seller_foxy_acc,
                buyer_token_acc, token_wallet_acc):
            self.buyer_foxy_acc = buyer_foxy_acc
            self.seller_foxy_acc = seller_foxy_acc
            self.buyer_token_acc = buyer_token_acc
            self.token_wallet_acc = token_wallet_acc

    class TransactionData:

        def __init__(self, rpc_response, nft_data):
            self.rpc_response = rpc_response
            self.nft_data = nft_data  

    class FFF_sniper:
        
        def __init__(self, token, phantom, price, proxy, rpc, delay, dshook, taskid):
            self.taskid = taskid
            params = {
                "roof": price*1000000000, # IN LAMPORTS
                "count": 1,
                "delay": delay,
                "threads": 1
            }
            self.task_info('log_task', 'Monitoring')
            self.task_info('status', 'Monitoring')
            Magic = FFFBot(
                phantom,
                rpc,
                proxy,
                params,
                token, 
                taskid
            )
            if Bot.localTasks[self.taskid]['status'] == 'STOP':
                Bot.localTasks.pop(self.taskid)
                return
            rpc_response, hook_price = Magic.sniper_threads()
            self.task_info('status', 'Success')
            self.task_info('log_task', 'Success')
            self.task_info('log_task', 'Send hook')
            DsHook.fff(token, hook_price, rpc_response['result'], dshook)

        def task_info(self, type, info):
            if type == 'all':
                Bot.localTasks[self.taskid]['status'] = info
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))
            elif type == 'status':
                Bot.localTasks[self.taskid]['status'] = info
            elif type == 'log':
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
            elif type == 'log_task':
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))

# ME
    class MagicEdenW3:
        
        def __init__(self, taskid, proxy):
            self.taskid = taskid
            self.httpx_client = httpx.Client(http2 = True)
            self.mint_address = None
            self.nft_data = None
            self.proxy = proxy
        
        def get_nft_data(self, mint_address, index):
            while True:
                try:
                    proxy_data = self.proxy[index].split(':')
                    
                    proxy = {
                            'http://' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                            'https://' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                    }
                    response = httpx.Client(http2 = True, proxies=proxy).get(
                        'https://api-mainnet.magiceden.io/rpc/getNFTByMintAddress/' + mint_address,
                        timeout = None,
                    ).json()
                    
                    nft_data = {
                        "mintAddress": response['results']['mintAddress'],
                        "owner": response['results']['owner'],
                        "id": response['results']['id'],
                        "price": response['results']['price'],
                        "creators": response['results']['creators'],
                    }  
                    
                    if response.get('results').get('title') is not None:
                        nft_data['title'] = response['results']['title']
                    if response['results'].get('escrowPubkey') is not None\
                    and response['results'].get('v2').get('auctionHouseKey') is not None\
                    and response['results'].get('v2').get('sellerReferral') is not None:
                        nft_data["escrowPubkey"] = response['results']['escrowPubkey']
                        nft_data["auctionHouseKey"] = response['results']['v2']['auctionHouseKey']
                        nft_data["sellerReferral"] = response['results']['v2']['sellerReferral']
                    
                    return nft_data 
                except:
                    logging.exception('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] <---MeSniper/get_nft_data--->')
                    
                    return None
        def get_message(self, buyer, nft_data):
            params = {
                "buyer": buyer,
                "seller": nft_data['owner'],
                "auctionHouseAddress": nft_data['auctionHouseKey'],
                "tokenMint": nft_data['mintAddress'],
                "tokenATA": nft_data['id'],
                "price": nft_data['price'],
                "sellerReferral": nft_data['sellerReferral'],
                "sellerExpiry": -1
            }
            headers = {
                'referer': 'https://magiceden.io/',
            }
            
            index = 0
            while True:
                try:
                    proxy_data = self.proxy[index].split(':')
                    proxy = {
                        'http://' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                        'https://' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                    }
                    index += 1
                    if index >= len(self.proxy):
                        index = 0
                    
                    message = httpx.Client(http2 = True, proxies=proxy).get(
                        'https://api-mainnet.magiceden.io/v2/instructions/buy_now',
                        params = params,
                        headers = headers,
                        timeout = None
                    ).json()
                    
                    self.message = message
                    
                    return message
                except:
                    logging.getLogger('MeSniper').error('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] Reconnecting')

        def create_transaction(self, message):
            message = SolanaMessage.deserialize(bytes(message['tx']['data']))
            signatures = [base58.b58encode(bytes([1] * SIG_LENGTH))]
            self.transaction = Transaction.populate(
                message,
                signatures
            )
        
        def send_transaction(self, connection, signer):
            try:
                rpc_response = connection.send_transaction(
                    self.transaction,
                    signer,
                    opts = TxOpts(
                        skip_confirmation = False,
                        preflight_commitment = Confirmed
                    )
                )
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] r:' + str(rpc_response))

                return rpc_response
            except:
                logging.exception('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] <---MeSniper/send_transaction--->')
        
        def simulate_transaction(self, connection, signer):
            self.transaction.sign(signer)
            rpc_response = connection.simulate_transaction(
                self.transaction,
            )
            
            return rpc_response
        
        def get_signatures(
                self, connection,
                proxy, current_signatures = [],
                proxies = {}):
            
            while True:
                try:
                    json = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getSignaturesForAddress",
                        "params": [
                            "M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K",
                            {
                                "limit": 50,
                                "commitment": "confirmed" 
                            }
                        ]
                    }
                    
                    if proxy is not None:
                        proxy_data = proxy.split(':')
                        proxies = {
                            'http' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                            'https' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                        }
                    
                    signatures = requests.post(
                        connection,
                        json = json,
                        proxies = proxies
                    ).json()['result']

                    for i in range(len(signatures)):
                        current_signatures.append(signatures[i]['signature'])
                    
                    return set(current_signatures)
                except:
                    logging.getLogger('MeSniper').error('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] get_signatures rate limit')
        
        @staticmethod
        def get_collection_mint(name, collection_mint = []):
            try:
                headers = {
                    "APIKeyID": "riKVjkjTmI2tflt",
                    "APISecretKey": "8AOnBfgDWTEuYrA" 
                }
                json = {
                    "name": name,
                    "name_search_method": "begins_with",
                    "network": "mainnet-beta"
                }
                response = requests.post(
                    "https://api.blockchainapi.com/v1/solana/nft/search",
                    json = json,
                    headers = headers
                ).json()

                for nft_metadata in response:
                    if nft_metadata.get("nft_metadata").get("mint") is not None:
                        collection_mint.append(nft_metadata["nft_metadata"]["mint"])
                
                return collection_mint
            except:
                logging.exception('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-[None] <---MeSniper/get_collection_mint--->')
        
        @staticmethod
        def create_keypair(b58_key):
            keypair = Keypair.from_secret_key(base58.b58decode(b58_key))
            return keypair
        
        def task_info(self, type, info):
            if type == 'all':
                Bot.localTasks[self.taskid]['status'] = info
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))
            elif type == 'status':
                Bot.localTasks[self.taskid]['status'] = info
            elif type == 'log':
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
            elif type == 'log_task':
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))

    class MagicEdenBot(MagicEdenW3):
        def __init__(self, phantom_key, rpc, proxies, proxylist, params, collection_mint, taskid, hook):
            super().__init__(taskid, proxies)
            self.taskid = taskid
            self.keypair = MagicEdenW3(taskid, proxies).create_keypair(
                phantom_key
            )
            self.rpc = rpc
            self.proxies = proxies
            self.proxylist= proxylist
            self.params = params
            self.collection_mint = collection_mint
            self.dshook = hook
            self.rpc_response = None
            self.success_nft_data = None
            self.success = None
            self.success_rpc_response = None
        
        def parse_nft(self, mint_address, roof):
            index = 0
            for i in range(50):
                nft_data = self.get_nft_data(
                    mint_address,
                    index
                )
                index += 1
                if index == len(self.proxy):
                    index = 0
                if nft_data is None:
                    continue
                if nft_data.get('escrowPubkey') is not None:  
                    if nft_data['price'] <= roof:
                        logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] Minting ' + str(nft_data))
                        self.task_info('log_task', 'Found new nft - price ' + str(nft_data['price']))
                        self.mint_address = mint_address
                        self.nft_data = nft_data
                        return None
        
        def check_transaction(
                self, signature,
                connection, proxy,
                proxies = {}):
            try:
                json = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getTransaction",
                    "params": [
                        signature,
                        "json"
                    ]
                }
                
                if proxy is not None:
                    proxy_data = proxy.split(':')
                    proxies = {
                        'http://' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1]),
                        'https://' : 'http://%s:%s@%s:%s' % (proxy_data[2], proxy_data[3], proxy_data[0], proxy_data[1])
                    }
                
                for i in range(10):
                    transaction = requests.post(
                        connection,
                        json = json,
                        proxies = proxies
                    ).json()
                    if transaction.get('result') is not None:
                        break
                
                if transaction.get('result') is None:
                    logging.getLogger('MeSniper').error('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] Transactions is None')
                if transaction.get('result').get('meta') is not None:
                    if 'err' in transaction['result']['meta']:
                        if transaction['result']['meta']['err'] is None:
                            if transaction['result']['meta'].get('postTokenBalances') is not None\
                            and len(transaction['result']['meta']['postTokenBalances']) != 0:
                                mint = transaction['result']['meta']['postTokenBalances'][0]['mint']
                                if mint in self.collection_mint:
                                    
                                    threading.Thread(
                                        target = self.parse_nft,
                                        args = (
                                            mint,
                                            self.params['roof'],
                                        )
                                    ).start()
            except:
                logging.getLogger('MeSniper').error('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] check_transaction rate limit')

        def parse_recent(self, connection, proxy_index = 0):
            current_signatures = self.get_signatures(connection, self.proxies[proxy_index])
            logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] Current signatures OK')

            while True:
                if self.success is True:
                    return None
                try:
                    if proxy_index >= len(self.proxies):
                            proxy_index = 0
                    signatures = self.get_signatures(
                        connection,
                        self.proxies[proxy_index]
                    )
                    
                    new_signatures = set(signatures) - current_signatures
                    current_signatures |= new_signatures

                    proxy_index += 1
                    for signature in list(new_signatures):
                        if proxy_index >= len(self.proxies):
                            proxy_index = 0
                        threading.Thread(
                            target = self.check_transaction,
                            args = (
                                signature,
                                connection,
                                self.proxies[proxy_index],
                            )
                        ).start()
                        
                        proxy_index += 1
                        time.sleep(self.params['delay'])
                except:
                    logging.exception('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] <---MeSniper/parse_recent--->')
        
        def parser_threads(self):
            for i in range(len(self.rpc)):
                for s in range(self.params['threads']):
                    
                    threading.Thread(
                        target = self.parse_recent,
                        args = (
                            self.rpc[i],
                        )
                    ).start()
                    time.sleep(0.25)

        def transaction_thread(self, connection):
            try:
                message = self.get_message(
                    self.keypair.public_key,
                    self.nft_data
                )
                nft_data = self.nft_data
                
                self.create_transaction(message)
                rpc_response = self.send_transaction(
                    connection,
                    self.keypair
                )
                
                self.rpc_response = rpc_response
                if ('None' not in str(self.rpc_response['result'])) and ('blockTime' not in str(self.rpc_response['result'])):
                    self.success = True
                    self.task_info('all', 'SUCCESS')
                    self.success_nft_data = nft_data
                    self.success_rpc_response = rpc_response
                else:
                    self.rpc_response = {'result': {'value': {'err': 'Error'}}}
                    self.success = False
            
            except:
                self.rpc_response = {'result': {'value': {'err': 'Error'}}}
                self.success = False
                self.rpc_response = None

        def sniper_threads(self, taskid, old_mint = None):
            self.taskid = taskid

            try:
                self.parser_threads()
                while True:
                    if Bot.localTasks[self.taskid]['status'] == 'STOP':
                        self.success = False
                        Bot.localTasks.pop(self.taskid)
                        self.task_info('log', 'Delete')
                        
                        return 'Stop', 'Stop', 'Stop'

                    if self.mint_address != old_mint:
                        threading.Thread(target=self.task_info, args=('status', 'Minting')).start
                        threading.Thread(target=self.task_info, args=('log_task', 'Minting')).start()
                        self.time = int(datetime.today().strftime("%S%f")[:-3])
                        old_mint = self.mint_address
                        self.rpc_response = None
                        self.success = None
                        
                        for i in range(len(self.rpc)):
                            for s in range(2):
                                threading.Thread(
                                    target = self.transaction_thread,
                                    args = (
                                        Client(self.rpc[i], commitment = Confirmed),
                                    )
                                ).start()
                        
                        while True:
                            if self.success == True:
                                checkoutTime = int(datetime.today().strftime("%S%f")[:-3]) - self.time
                                if '-' in str(checkoutTime):
                                    checkoutTime = 60000 + checkoutTime
                                return self.success_rpc_response, self.success_nft_data, checkoutTime
                            elif self.success == False:
                                threading.Thread(target=self.task_info, args=('log_task', 'Minting failed')).start()
                                threading.Thread(target=self.task_info, args=('status', 'Monitoring')).start()
                                threading.Thread(target=self.task_info, args=('log_task', 'Monitoring')).start()
                                break
            except:
                logging.exception('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+str(self.taskid)+'] <---MeSniper/sniper_threads--->')
        
        def task_info(self, type, info):
            if type == 'all':
                Bot.localTasks[self.taskid]['status'] = info
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))
            elif type == 'status':
                Bot.localTasks[self.taskid]['status'] = info
            elif type == 'log':
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
            elif type == 'log_task':
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))

    class Sniper:
        def __init__(self, collection, price, delay, threads, phantom, rpc, proxy, proxylist, taskid, dshook):
            self.taskid = taskid
            self.dshook = dshook
            self.proxy = proxy
            collection_mint = self.collect(collection)
            self.task_info('log_task', 'Total items - ' + str(len(collection_mint)))
            params = {
                "roof": price,
                "delay": delay,
                "threads": threads
            }
            if Bot.localTasks[self.taskid]['status'] == 'STOP':
                Bot.localTasks.pop(self.taskid)
                self.task_info('log', 'Delete')
                
                return
            
            self.task_info('all', 'Monitoring')
            
            Magic = MagicEdenBot(
                phantom,
                rpc,
                proxy,
                proxylist,
                params,
                collection_mint,
                taskid,
                dshook
            )
            
            if Bot.localTasks[self.taskid]['status'] == 'STOP':
                Bot.localTasks.pop(self.taskid)
                self.task_info('log', 'Delete')
                return
            
            response, hook, checkoutTime = Magic.sniper_threads(taskid)
            if response == 'Stop' and hook == 'Stop':
                return
            
            self.task_info('all', 'SUCCESS')

            try:
                product = hook['title']
            except:
                product = None
            
            self.task_info('log_task', 'Send hook')
            DsHook.me(product, [hook['price'], price], proxylist, checkoutTime, response['result'], dshook)
            self.task_info('log_task', 'End')

        def collect(self, name):
            try:
                collect = json.load(open('collections/'+name + '.json', 'r'))

                return collect
            except:
                self.task_info('log_task', 'Gets collection')
                collect = MagicEdenW3(self.taskid, self.proxy).get_collection_mint(name)
                open('collections/'+name+'.json', 'w+').write(json.dumps(collect))

                return collect

        def task_info(self, type, info):
            if type == 'all':
                Bot.localTasks[self.taskid]['status'] = info
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))
            elif type == 'status':
                Bot.localTasks[self.taskid]['status'] = info
            elif type == 'log':
                logging.getLogger('MeSniper').info('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+']-['+ str(self.taskid)+'] '+info)
            elif type == 'log_task':
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))

# Bybit
    class Bybit:
        def __init__(self, usertoken, useragent, id, proxy, timer, taskid, hook, key):
            try:
                self.taskid = taskid
                self.success = None
                
                captcha_time = timer[:6] + '0'+ timer[-4:]
                
                headers = {
                    'accept-language': 'ru-ru',
                    'origin': 'https://www.bybit.com',
                    'user-agent': useragent,
                    'usertoken': usertoken,
                }
                
                self.prox = {
                    'http': 'http://' + proxy,
                    'https': 'http://' + proxy
                }
                
                self.task_info('all', 'Wait timer')

                while datetime.today().strftime("%H:%M:%S:%f")[:-4] != captcha_time:
                    if Bot.localTasks[self.taskid]['status'] == 'STOP':
                        Bot.localTasks.pop(self.taskid)
                        
                        self.task_info('log', 'Delete')
                        
                        return
                
                self.task_info('all', 'Gen')
                
                if Bot.localTasks[self.taskid]['status'] == 'STOP':
                    Bot.localTasks.pop(self.taskid)
                    self.task_info('log', 'Delete')
                    
                    return

                captchalist = self.captcha(headers, key)

                if Bot.localTasks[self.taskid]['status'] == 'STOP':
                    Bot.localTasks.pop(self.taskid)

                    self.task_info('log', 'Delete')
                    
                    return
                
                self.task_info('log', 'Captcha token bank ' + str(len(captchalist)))
                self.task_info('log_task', 'Captcha token bank ' + str(len(captchalist)))
                
                while datetime.today().strftime("%H:%M:%S:%f")[:-4] != timer:
                    if Bot.localTasks[self.taskid]['status'] == 'STOP':
                        Bot.localTasks.pop(self.taskid)

                        self.task_info('log', 'Delete')

                        return
                
                self.task_info('all', 'Buying')
                
                for i in range(len(captchalist)):
                    if Bot.localTasks[self.taskid]['status'] == 'STOP':
                        Bot.localTasks.pop(self.taskid)

                        self.task_info('log', 'Delete')

                        return
                    
                    if self.success != None:
                        return
                    
                    json_data = {
                        'merchandiseId': id, 
                        'humanVerifyToken': captchalist[i]
                    }
                    
                    threading.Thread(target=self.buy_v2, args=(headers, json_data)).start()
                    time.sleep(0.13)
                    
                    threading.Thread(target=self.buy_v1, args=(headers, json_data)).start()
                    time.sleep(0.13)

                time.sleep(20)
                if self.success != None:
                    self.task_info('all', 'SUCCESS')
                    
                    try:
                        product = self.success['result']['name']
                    except:
                        product = None
                        
                    try:
                        price = self.success['result']['price'][:5]
                    except:
                        price = None
                        
                    try:
                        proxy_hook = proxy.split('@')[-1].split(':')[0]
                    except:
                        proxy_hook = None
                        
                    DsHook.bybit(product, price, taskid, proxy_hook, timer, id, hook)

                    self.task_info('all', 'End.')
                else:
                    self.task_info('log', 'Success not found')
                    self.task_info('all', 'End.')
            except:
                Bot.localTasks[self.taskid]['status'] = 'Error'
                
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--Bybit--> Task: ' + str(taskid))
        
        def buy_v2(self, headers, json_data):
            try:
                response = requests.post('https://api2.bybit.com/spot/api/nft/v2/order/buy', headers=headers, json=json_data, proxies=self.prox)

                self.task_info('log', 'v2 r:'+str(response.json()))

                if response.json()['success'] == True:
                    self.success = response.json()
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--Buy v2--> Task: ' + str(self.taskid))
        
        def buy_v1(self, headers, json_data):
            try:
                response = requests.post('https://api2.bybit.com/spot/api/nft/v1/order/buy/normal', headers=headers, json=json_data, proxies=self.prox)

                self.task_info('log', 'v1 r:'+str(response.json()))

                if response.json()['success'] == True:
                    self.success = response.json()
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--Buy v1--> Task: ' + str(self.taskid))
        
        def task_info(self, type, info):
            if type == 'all':
                Bot.localTasks[self.taskid]['status'] = info
                logging.getLogger('Bybit').info('('+datetime.today().strftime("%H:%M:%S:%f")[:-4]+')Task'+ str(self.taskid)+' '+info)
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))

            elif type == 'status':
                Bot.localTasks[self.taskid]['status'] = info

            elif type == 'log':
                logging.getLogger('Bybit').info('('+datetime.today().strftime("%H:%M:%S:%f")[:-4]+')Task'+ str(self.taskid)+' '+info)

            elif type == 'log_task':
                Bot.localTasks[self.taskid]['logs'].append(str('['+datetime.today().strftime("%H:%M:%S:%f")[:-4]+'] '+info))
        
        def captcha(self, headers, key):
            self.list = []
            
            for i in range(50):
                threading.Thread(target=self.geetest, args=(headers, key)).start()
                time.sleep(0.4)
            time.sleep(30)
        
            return self.list
        
        def geetest(self, headers, key):
            try:
                params = {
                    'sourceType': 'web',
                    'guid': '0',
                }
                
                response = requests.get('https://api2.bybit.com/spot/api/nft/v1/geetest/register', headers=headers, params=params)
                
                if response.json()['ret_code'] != 0:
                    return
                
                challenge1 = json.loads(response.json()['result']['data'])['challenge']
                gt1 = json.loads(response.json()['result']['data'])['gt']
                
                ANTICAPTCHA_KEY = key
                websiteURL = "https://api2.bybit.com/spot/api/nft/v1/verify"
                gt = json.loads(response.json()['result']['data'])['gt']
                challenge = json.loads(response.json()['result']['data'])['challenge']
                result = GeeTestTaskProxyless.GeeTestTaskProxyless(anticaptcha_key=ANTICAPTCHA_KEY,
                websiteURL=websiteURL,
                gt=gt).captcha_handler(challenge=challenge)
                
                if result['errorId'] != 0:
                    return 
                
                json_data = {
                    'challenge': challenge1,
                    'validate': result['solution']['validate'],
                    'seccode': result['solution']['seccode'],
                }    

                response = requests.post('https://api2.bybit.com/spot/api/nft/v1/verify', headers=headers, json=json_data)
                
                if response.json()['ret_code'] != 0:
                    return
                
                self.list.append(response.json()['result']['verifyToken'])
            except:
                Bot.localTasks[self.taskid]['status'] = 'Error'
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--Geetest--> Task: ' + str(self.taskid))

    class Veve:
        try:
            def __init__(self, proxy, login, password, drop_id, drop_type, timer, api, hook, name_task, task_id):
                self.main_headers = {
                    'user-agent': None,
                    'accept-encoding': 'gzip, deflate, br',
                    'accept': '*/*',
                    'Connection': 'keep-alive',
                    'content-type': 'application/json',
                    'client-version': '1.0.588',
                    'origin': 'https://omi.veve.me',
                    'x-kpsdk-ct': None,
                    'x-kpsdk-cd': None,
                    'client-operation': None,
                    'client-name': 'veve-app-ios',
                    'client-model': 'iphone 11 pro max',
                    'client-brand': 'apple',
                    'client-manufacturer': 'apple',
                    'client-user-id': None,
                    'client-id': None,
                    'accept-language': 'en-us',
                    'x-kpsdk-v': 'i-1.6.0',
                    'client-installer': 'appstore',
                    'client-carrier': 'unknown'
                }
                
                self.operations()
                self.login = login
                self.password = password
                self.proxy = proxy
                self.drop_id = drop_id
                self.drop_type = drop_type
                self.timer = timer
                self.name_task = name_task
                self.task_id = task_id
                self.api = api
                self.hook = hook
                self.captcha_list = []
                self.run = True
                
                if self.proxy != None:
                    self.ip = 'proxy'
                else:
                    self.ip = 'local'
                
                Bot.localTasks[self.task_id]['status'] = 'Casada bypass'

                self.get_ct()
            
            def get_ct(self):
                self.useragent = self.get_useragent()
                
                headers = {
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "accept-encoding": "gzip, deflate, br",
                    "x-kpsdk-v": 'i-1.6.0',
                    "accept-language": "en-us",
                    "user-agent": self.useragent,
                }
                
                if self.proxy != None:
                    r = requests.get('https://mobile.api.prod.veve.me/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp', headers=headers, proxies=self.proxy)
                else:
                    r = requests.get('https://mobile.api.prod.veve.me/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp', headers=headers)
                
                if r.status_code == 429:
                    headers['referer'] = 'https://mobile.api.prod.veve.me/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp'

                    r = requests.get(f'https://mobile.api.prod.veve.me/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/ips.js?KP_UIDz={r.headers["x-kpsdk-ct"]}&x-kpsdk-v=i-1.6.0', headers=headers)

                    kasada_data = self.parse_ips(r.content)
                    
                    headers = {
                            "accept": "*/*",
                            "content-type": "application/octet-stream",
                            "accept-encoding": "gzip, deflate, br",
                            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                            "referer": f"https://mobile.api.prod.veve.me/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp",
                            "origin": 'https://mobile.api.prod.veve.me/',
                            "x-kpsdk-v": 'i-1.6.0',
                            "user-agent": self.useragent,
                            "x-kpsdk-ct": kasada_data["x_kpsdk_ct"]
                        }

                    data = gzip.decompress(base64.b64decode(kasada_data['tl_body_b64']))

                    r = requests.post('https://mobile.api.prod.veve.me/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/tl', data=data, headers=headers)

                    self.kpsdk_ct = r.headers['x-kpsdk-ct']
                    
                    self.check_ct()
            
            def check_ct(self):
                self.main_headers['x-kpsdk-ct'] = self.kpsdk_ct
                self.main_headers['client-operation'] = 'AppMetaInfo'
                self.main_headers['client-user-id'] = str(uuid.uuid4())
                self.main_headers['client-id'] = str(uuid.uuid4())
                self.main_headers['user-agent'] = self.useragent
                self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()
                
                data = {
                    'operationName':'AppMetaInfo',
                    'variables':{'client':'IOS'},
                    "query": "query AppMetaInfo($client: SupportedClients!) {  minimumVersion(client: $client)  featureFlagList {    name    enabled    __typename  }}"
                }
                
                if self.proxy != None:
                    r = requests.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=data, proxies=self.proxy)
                else:
                    r = requests.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=data)
                
                if r.status_code == 200:
                    self.auth(False)
                else:
                    self.get_ct()
            
            def get_useragent(self):
                headers = {'Authorization': 'Bearer ...'}
                params = {'sessionid': 'thefe@rambler.ru', 'platform': 'IOS', 'locale': 'zh_CN'}
                r = requests.post('https://us.unicorn-bot.com/api/session/init/', json=params, headers=headers, verify=False)
                if r.status_code not in [200, 201, 202, 203, 204, 205, 206]:
                    self.run = False
                    
                    Bot.localTasks[self.task_id]['status'] = 'Error UA'
                else:
                    self.XSESSION = r.cookies['XSESSIONDATA']
                    
                    return r.json()['user_agent']
            
            def parse_ips(self, ips):
                ips = gzip.compress(ips)
                
                headers = {'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjUwMjgxNjQ0LCJpYXQiOjE2NDc2ODk2NDQsImp0aSI6ImQ3ZjNkNTUzNjZjNjQ5ODhhMjUyZGI2YWM5NDYwYTM5IiwidXNlcl9pZCI6NTJ9.ggpmwDBftXd_IPmgn7YQBkNdckFcVE40m_pzZcvc9rg'}
                data = {
                    'host': 'https://mobile.api.prod.veve.me', 
                    'compress_method': 'GZIP', 
                    'kpver': 'v202107',
                    'cookie': None,  
                    'cookiename': None,
                    'site': None, 
                    'proxy_uri': None, 
                }
                
                r = requests.post('https://us.unicorn-bot.com/api/kpsdk/ips/', data=data, headers=headers, files={'ips_js': ips}, verify=False, cookies={'XSESSIONDATA': self.XSESSION})    

                return r.json()

            def get_veve_answers(self):
                timestamp = int(datetime.timestamp(datetime.now()) * 1000)
                _0x29e57c = []
                veve_id = self.get_veve_id()
                difficulity = 10
                subchallengeCount = 2
                pre_hash = 'tp-v2-input' + ',\x20' + str(timestamp) + ',\x20' + veve_id
                _0x189324 = sha256(pre_hash.encode('utf-8')).hexdigest()
                _0x5ca237 = difficulity / subchallengeCount
                _0x470f72 = 0
                
                while _0x470f72 < subchallengeCount:
                    _0xeb1b23 = 1
                    
                    while True:
                        currect_hash = str(_0xeb1b23) + ',\x20' + _0x189324
                        
                        _0x2b3d00 = sha256(currect_hash.encode('utf-8')).hexdigest()
                        if self.hash_difficulty(_0x2b3d00) >= _0x5ca237:
                            _0x29e57c.append(_0xeb1b23)
                            _0x189324 = _0x2b3d00
                            break

                        _0xeb1b23 += 1
                    _0x470f72 += 1
                    
                return f'{"{"}"workTime": {timestamp}, "id": "{veve_id}", "answers": {_0x29e57c}{"}"}'
            
            def get_veve_id(self):
                var = ''
                for i in range(32):
                    var += '0123456789abcdef'[math.floor(16 * random.uniform(0, 1))]
                    
                return var

            def hash_difficulty(self, hash):
                hash = 0x10000000000000 / int('0x' + hash[0:13], 16)
                return hash
            
            def window(self, name):
                try:
                    def get_text():
                        global inpt
                        inpt = text.get(1.0, END)
                        root.destroy()
                    def resend():
                        threading.Thread(target=self.auth, args=(True,)).start()
                    
                    root = Tk()
                    root.title('Infinite TOTP')
                    root.resizable(height = False, width = False)
                    root.configure(background='white')

                    label = Label(text=name, width=25)
                    label.configure(background='grey')
                    label.pack()
                    
                    text = Text(width=22, height=4)
                    text.configure(background='white')
                    text.pack()
                    
                    frame = Frame()
                    frame.pack()
                    
                    Button(frame, text="OK!", width=11,
                        command=get_text).pack(side=RIGHT)
                    
                    Button(frame, text="Resend", width=11,
                        command=resend).pack(side=LEFT)
                    
                    root.attributes("-topmost", True)
                    root.mainloop()
                    
                    return inpt.strip()
                except:
                    logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--WINDOW-->')
            
            def captcha(self):
                from python3_anticaptcha import HCaptchaTaskProxyless
                
                ANTICAPTCHA_KEY = self.api
                WEB_URL = "https://discord.com/login"
                SITE_KEY = '86c60170-2a73-489f-89ad-fca627914423'
                
                result = HCaptchaTaskProxyless.HCaptchaTaskProxyless(anticaptcha_key = ANTICAPTCHA_KEY).\
                captcha_handler(websiteURL = WEB_URL, websiteKey = SITE_KEY)
                self.captcha_list.append(result['solution']['gRecaptchaResponse'])

                return result['solution']['gRecaptchaResponse']
            
            def auth(self, no_window):
                try:
                    Bot.localTasks[self.task_id]['status'] = 'Login'
                    
                    self.main_headers['client-operation'] = None
                    self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()
                    data = '{"email":"' + str(self.login) + '"}'
                    
                    self.session = requests.Session()
                    if self.proxy != None:
                        r = self.session.post('https://mobile.api.prod.veve.me/api/auth/totp/send', headers=self.main_headers, data=data, proxies=self.proxy)
                    else:
                        r = self.session.post('https://mobile.api.prod.veve.me/api/auth/totp/send', headers=self.main_headers, data=data)
                    
                    if no_window == False:
                        Bot.localTasks[self.task_id]['status'] = 'Wait totp'
                        
                        totp = self.window(self.login)
                        self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()

                        data = '{"email":"' + str(self.login) + '","password":"' + str(self.password) + '","totp":"' + str(totp) + '"}'
                        if  self.proxy != None:
                            r = self.session.post('https://mobile.api.prod.veve.me/api/auth/login', headers=self.main_headers, data=data, proxies=self.proxy)
                        else:
                            r = self.session.post('https://mobile.api.prod.veve.me/api/auth/login', headers=self.main_headers, data=data)
                        if 'true' in r.text:
                            Bot.localTasks[self.task_id]['status'] = 'Successfully login'
                            self.buy()
                        else:
                            Bot.localTasks[self.task_id]['status'] = 'Error login'
                except:
                    logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--AUTH-->')
            
            def buy(self):
                self.main_headers['client-operation'] = None
                self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()
                
                Bot.localTasks[self.task_id]['status'] = 'Wait Time'

                captcha_time = self.timer.split(':')
                captcha_time = captcha_time[0] + ':' + captcha_time[1] + ':' + str(int(captcha_time[2]) - 40) + ':' + captcha_time[3]

                while captcha_time != datetime.today().strftime("%H:%M:%S:%f")[:-4]:
                    pass

                Bot.localTasks[self.task_id]['status'] = 'Captcha generate'
                
                if Bot.localTasks[self.task_id]['status'] != 'STOP':
                    while self.timer != datetime.today().strftime("%H:%M:%S:%f")[:-4]:
                        pass
                    
                    Bot.localTasks[self.task_id]['status'] = 'Reservation'
                    
                    while self.run == True:
                        self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()
                        
                        if self.drop_type == 'comics':
                            self.main_headers['client-operation'] = 'PlaceStoreReservation'
                            self.comic_buy_data['variables']['id'] = str(self.drop_id)
                            if self.proxy != None:
                                r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.comic_buy_data, proxies=self.proxy)
                            else:
                                r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.comic_buy_data)
                            
                            try:
                                test = r.json()['data']['placeStoreReservation']['id']

                                Bot.localTasks[self.task_id]['status'] = 'Successfully reservation'
                                
                                try:
                                    number = r.json()['data']['placeStoreReservation']['issueNumber']
                                except:
                                    number = 'No'
                                
                                time.sleep(10)
                                self.main_headers['client-operation'] = 'StorePurchaseMutation'
                                self.comic_purchase_data['variables']['captchaSiteKey'] = '86c60170-2a73-489f-89ad-fca627914423'
                                
                                try:
                                    self.comic_purchase_data['variables']['captchaCode'] = self.captcha_list[0]
                                except:
                                    try:
                                        self.comic_purchase_data['variables']['captchaCode'] = self.captcha()
                                    except:
                                        self.stop = True

                                        Bot.localTasks[self.task_id]['status'] = 'Captcha error'
                                
                                self.comic_purchase_data['variables']['id'] = self.drop_id
                                self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()
                                
                                if self.proxy != None:
                                    r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.comic_purchase_data, proxies=self.proxy)
                                else:
                                    r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.comic_purchase_data)
                                
                                Bot.localTasks[self.task_id]['status'] = 'SUCCESS'

                                self.successhook(self.name_task, self.timer, self.ip, self.drop_id, 'None')
                                
                                self.stop = True

                            except:
                                try:
                                    if Bot.localTasks[self.task_id]['status'] != 'STOP':
                                        self.stop = True
                                    elif r.json()['errors'][0]['message'] == 'There are no available store purchase reservations for this element':
                                        Bot.localTasks[self.task_id]['status'] = 'SOLD OUT'
                                        self.stop = True
                                except:pass
                        
                        elif self.drop_type == 'blindbox':
                            self.main_headers['client-operation'] = 'PlaceStoreReservationForBlindbox'
                            self.blindbox_buy_data['variables']['id'] = str(self.drop_id)
                            if self.proxy != None:
                                r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.blindbox_buy_data, proxies=self.proxy)
                            else:
                                r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.blindbox_buy_data)
                            
                            try:
                                test = r.json()['data']['placeBlindboxReservation']['id']
                                
                                Bot.localTasks[self.task_id]['status'] = 'Successfully reservation'
                                
                                time.sleep(10)
                                self.main_headers['client-operation'] = 'StoreBlindBoxPurchaseMutation'
                                self.blindbox_purchase_data['variables']['captchaSiteKey'] = '86c60170-2a73-489f-89ad-fca627914423'

                                try:
                                    self.comic_purchase_data['variables']['captchaCode'] = self.captcha_list[0]
                                except:
                                    try:
                                        self.comic_purchase_data['variables']['captchaCode'] = self.captcha()
                                    except:
                                        self.stop = True
                                        Bot.localTasks[self.task_id]['status'] = 'Captcha error'
                                
                                self.blindbox_purchase_data['variables']['id'] = self.drop_id
                                self.main_headers['x-kpsdk-cd'] = self.get_veve_answers()
                                if self.proxy != None:
                                    r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.blindbox_purchase_data, proxies=self.proxy)
                                else:
                                    r = self.session.post('https://mobile.api.prod.veve.me/graphql', headers=self.main_headers, json=self.blindbox_purchase_data)
                                
                                Bot.localTasks[self.task_id]['status'] = 'SUCCESS'
                                
                                try:
                                    self.successhook(self.name_task, self.timer, self.ip, self.drop_id, 'None')
                                except:
                                    pass

                                self.stop = True
                            except:
                                try:
                                    if Bot.localTasks[self.task_id]['status'] != 'STOP':
                                        self.stop = True
                                    elif r.json()['errors'][0]['message'] == 'There are no available store purchase reservations for this element':
                                        Bot.localTasks[self.task_id]['status'] = 'SOLD OUT'
                                        self.stop = True
                                except:pass
            def operations(self):
                check_data_query = '''query MyInfo {
                me {
                    id
                    firstName
                    lastName
                    username
                    email
                    statuses
                    createdAt
                    dateOfBirth
                    __typename
                }
                }'''
                check_data = {
                "operationName": "MyInfo",
                "variables": {},
                "query": check_data_query
                }
                check_account_query = '''query bootstrapQuery {
                me {
                    id
                    email
                    emailConfirmed
                    onBoardingComplete
                    totalUnreadNotifications
                    firstName
                    lastName
                    username
                    gender
                    dateOfBirth
                    country
                    createdAt
                    marketBlockedUntil
                    blockedFeatures(first: 10) {
                    edges {
                        node {
                        feature
                        active
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                }'''
                check_account_data = {
                "operationName": "bootstrapQuery",
                "variables": {},
                "query": check_account_query
                }
                drop_data_query = '''query StoreLandingQuery($now: DateTime!, $thisMonth: DateTime!) {
                latestDrops: storeDropList(
                    first: 5
                    sortOptions: {sortBy: DROP_DATE, sortDirection: DESCENDING}
                    filterOptions: {dropDate: {type: BEFORE, date: $now}}
                ) {
                    edges {
                    node {
                        ... on Series {
                        ...LandscapeCollectibleSeries
                        __typename
                        }
                        ... on ComicType {
                        ...LandscapeComicSeries
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                brands: brandList(
                    first: 5
                    sortOptions: {sortBy: POPULARITY, sortDirection: DESCENDING}
                ) {
                    edges {
                    node {
                        ...SquareBrand
                        series(first: 1) {
                        totalCount
                        edges {
                            node {
                            id
                            name
                            __typename
                            }
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                newCollectibles: collectibleTypeList(
                    first: 5
                    sortOptions: {sortBy: DROP_DATE, sortDirection: DESCENDING}
                ) {
                    edges {
                    node {
                        ...EcomiCardCollectible
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                newComics: comicTypeList(first: 5) {
                    edges {
                    node {
                        ...EcomiCardComic
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                endingSoon: seriesList(
                    first: 5
                    sortOptions: {sortBy: END_DATE, sortDirection: ASCENDING}
                    filterOptions: {endDate: [{type: BEFORE, date: $thisMonth}, {type: AFTER, date: $now}]}
                ) {
                    edges {
                    node {
                        ...SquareSeries
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                comingSoon: storeDropList(
                    first: 5
                    sortOptions: {sortBy: DROP_DATE, sortDirection: ASCENDING}
                    filterOptions: {dropDate: {type: AFTER, date: $now}}
                ) {
                    edges {
                    node {
                        ... on Series {
                        ...LandscapeCollectibleSeries
                        __typename
                        }
                        ... on ComicType {
                        ...LandscapeComicSeries
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                popular: collectibleTypeList(
                    first: 5
                    sortOptions: {sortBy: POPULARITY, sortDirection: DESCENDING}
                ) {
                    edges {
                    node {
                        ...EcomiCardCollectible
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                sellingFast: collectibleTypeList(
                    first: 5
                    sortOptions: {sortBy: AVAILABILITY, sortDirection: ASCENDING}
                ) {
                    edges {
                    node {
                        ...EcomiCardCollectible
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                recentlyViewed: collectibleTypeList(
                    first: 5
                    sortOptions: {sortBy: VIEW_DATE, sortDirection: DESCENDING}
                    filterOptions: {viewedByUser: true}
                ) {
                    edges {
                    node {
                        ...EcomiCardCollectible
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                ending: collectibleTypeList(
                    first: 0
                    sortOptions: {sortBy: DROP_DATE, sortDirection: ASCENDING}
                    filterOptions: {hasEndDate: true}
                ) {
                    totalCount
                    __typename
                }
                coming: collectibleTypeList(
                    first: 0
                    sortOptions: {sortBy: DROP_DATE, sortDirection: ASCENDING}
                    filterOptions: {comingSoonAfterSeriesDrop: true}
                ) {
                    totalCount
                    __typename
                }
                }
                fragment LandscapeCollectibleSeries on Series {
                id
                image: landscapeImage {
                    id
                    url
                    __typename
                }
                dropDate
                totalCollectibleTypes
                collectibleTypes(first: 1) {
                    edges {
                    node {
                        id
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                __typename
                }
                fragment LandscapeComicSeries on ComicType {
                id
                image: landscapeImage {
                    id
                    url
                    __typename
                }
                dropDate
                __typename
                }
                fragment SquareSeries on Series {
                id
                image: squareImage {
                    id
                    url
                    __typename
                }
                dropDate
                totalCollectibleTypes
                collectibleTypes(first: 1) {
                    edges {
                    node {
                        id
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                __typename
                }
                fragment EcomiCardCollectible on CollectibleType {
                id
                name
                rarity
                hideMedia
                image {
                    id
                    url
                    direction
                    __typename
                }
                storePrice
                totalAvailable
                totalIssued
                availableReservations
                storeCurrencyType
                timeUntilDropDate
                series {
                    id
                    isBlindbox
                    timeUntilDropDate
                    availableReservations
                    __typename
                }
                __typename
                }
                fragment EcomiCardComic on ComicType {
                id
                name
                storePrice
                totalOwnedComicsByUser
                totalAvailable
                totalIssued
                description
                comicNumber
                startYear
                cover {
                    id
                    image {
                    id
                    url
                    direction
                    __typename
                    }
                    __typename
                }
                __typename
                }
                fragment SquareBrand on Brand {
                id
                name
                image: squareImage {
                    id
                    url
                    __typename
                }
                __typename
                }'''
                drop_data = {
                "operationName": "StoreLandingQuery",
                "variables": {
                },
                "query": drop_data_query
                }
                comic_info_query = '''fragment Comic on ComicType {
                id
                name
                description
                totalIssued
                totalAvailable
                totalStoreAllocation
                storePrice
                availableReservations
                pendingStorePurchasesForUser
                availableForStorePurchase
                unableToStorePurchaseReason
                storeCurrencyType
                isUnlimited
                isFree
                timeUntilDropDate
                covers(first: 10) {
                    edges {
                    node {
                        id
                        rarity
                        totalIssued
                        totalAvailable
                        totalStoreAllocation
                        image {
                        id
                        url
                        type
                        direction
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    totalCount
                    __typename
                }
                totalOwnedComicsByUser
                totalLikes
                totalBookmarks
                likedByUser
                bookmarkedByUser
                totalComments
                comicNumber
                pageCount
                startYear
                minimumAge
                cover {
                    id
                    rarity
                    image {
                    id
                    url
                    type
                    direction
                    __typename
                    }
                    __typename
                }
                artists(first: 10) {
                    totalCount
                    edges {
                    node {
                        id
                        name
                        __typename
                    }
                    __typename
                    }
                    totalCount
                    __typename
                }
                writers(first: 10) {
                    totalCount
                    edges {
                    node {
                        id
                        name
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                characters(first: 10) {
                    totalCount
                    edges {
                    node {
                        id
                        name
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                comicSeries {
                    id
                    name
                    publisher {
                    id
                    name
                    __typename
                    }
                    __typename
                }
                pagesMedia(first: 5) {
                    totalCount
                    edges {
                    node {
                        id
                        url
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                __typename
                }
                query ComicQuery($comicTypeId: ID!, $hasListing: Boolean!, $marketListingId: ID!, $comicId: ID!, $hasComicId: Boolean!, $marketEnabled: Boolean!) {
                comicType(id: $comicTypeId) {
                    ...Comic
                    __typename
                }
                comic(id: $comicId) @include(if: $hasComicId) @skip(if: $hasListing) {
                    id
                    ownedByUser
                    issueNumber
                    openMarketListingId @include(if: $marketEnabled)
                    readingStatus
                    transactions {
                    edges {
                        node {
                        id
                        createdAt
                        amountGem
                        feeGem
                        amountUsd
                        buyer {
                            id
                            username
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    cover {
                    id
                    rarity
                    floorMarketPrice
                    totalMarketListings
                    totalOwnedComicsByUser
                    image {
                        id
                        url
                        type
                        direction
                        __typename
                    }
                    totalIssued
                    artists(first: 10) {
                        totalCount
                        edges {
                        node {
                            id
                            name
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    comicType {
                    ...Comic
                    __typename
                    }
                    __typename
                }
                marketListing(id: $marketListingId) @include(if: $hasListing) {
                    id
                    createdAt
                    status
                    listingType
                    endingAt
                    price: currentPrice
                    currentPrice
                    userBidPosition
                    seller {
                    id
                    username
                    __typename
                    }
                    marketMetadata {
                    totalMarketListings
                    __typename
                    }
                    bids(first: 1) {
                    totalCount
                    edges {
                        node {
                        id
                        createdAt
                        price
                        status
                        bidder {
                            id
                            username
                            avatar {
                            id
                            url
                            __typename
                            }
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    element {
                    ... on Comic {
                        id
                        issueNumber
                        ownedByUser
                        readingStatus
                        openMarketListingId @include(if: $marketEnabled)
                        comicType {
                        ...Comic
                        __typename
                        }
                        cover {
                        id
                        rarity
                        image {
                            id
                            url
                            type
                            direction
                            __typename
                        }
                        totalIssued
                        totalMarketListings
                        floorMarketPrice
                        totalOwnedComicsByUser
                        artists(first: 10) {
                            edges {
                            node {
                                id
                                name
                                __typename
                            }
                            __typename
                            }
                            totalCount
                            __typename
                        }
                        __typename
                        }
                        transactions {
                        edges {
                            node {
                            id
                            createdAt
                            amountGem
                            feeGem
                            amountUsd
                            buyer {
                                id
                                username
                                __typename
                            }
                            __typename
                            }
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                }'''
                comic_info = {
                "operationName": "ComicQuery",
                "variables": {
                    "hasListing": False,
                    "marketListingId": "",
                    "comicId": "",
                    "hasComicId": False,
                    "marketEnabled": True
                },
                "query": comic_info_query
                }
                comic_buy_data_query = '''mutation PlaceStoreReservation($id: ID!) {
                placeStoreReservation(elementId: $id) {
                    element {
                    availableReservations
                    id
                    isFree
                    isUnlimited
                    storePrice
                    totalAvailable
                    totalIssued
                    ... on ComicType {
                        id
                        name
                        __typename
                    }
                    __typename
                    }
                    expiresAt
                    id
                    issueNumber
                    status
                    __typename
                }
                }'''
                self.comic_buy_data = {
                "operationName": "PlaceStoreReservation",
                "variables": {
                },
                "query": comic_buy_data_query
                }
                comic_purchase_query = '''mutation StorePurchaseMutation($id: ID!, $captchaCode: String!, $captchaSiteKey: String!) {
                storePurchase(
                    elementId: $id
                    captchaCode: $captchaCode
                    captchaSiteKey: $captchaSiteKey
                ) {
                    id
                    status
                    buyer {
                    gemBalance
                    __typename
                    }
                    collectibles {
                    formattedIssueNumber
                    __typename
                    }
                    __typename
                }
                }'''
                self.comic_purchase_data = {
                "operationName": "StorePurchaseMutation",
                "variables": {
                },
                "query": comic_purchase_query
                }
                collectible_data_query = '''fragment Collectible on CollectibleType {
                id
                name
                description
                totalIssued
                totalAvailable
                dropDate
                endDate
                storePrice
                floorMarketPrice
                soldOutDate
                variety
                availableReservations
                pendingStorePurchasesForUser
                availableForStorePurchase
                unableToStorePurchaseReason
                timeUntilDropDate
                storeCurrencyType
                editionType
                isUnlimited
                isFree
                images(first: 10) {
                    edges {
                    node {
                        id
                        url
                        type
                        direction
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                rarity
                hashtags(first: 1) {
                    edges {
                    node {
                        id
                        text
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                licensor {
                    id
                    ...StoreLicensorRequiredProps
                    __typename
                }
                brand {
                    id
                    series(first: 1) {
                    totalCount
                    edges {
                        node {
                        id
                        name
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    ...StoreBrandRequiredProps
                    __typename
                }
                series {
                    id
                    season
                    isBlindbox
                    ...StoreSeriesRequiredProps
                    __typename
                }
                totalOwnedByUser
                totalLikes
                totalBookmarks
                likedByUser
                bookmarkedByUser
                totalComments
                image {
                    id
                    url
                    type
                    direction
                    __typename
                }
                __typename
                }
                query CollectibleQuery($id: ID!, $hasListing: Boolean!, $marketListingId: ID!, $collectibleId: ID!, $hasCollectibleId: Boolean!, $marketEnabled: Boolean!) {
                collectibleType(id: $id) {
                    ...Collectible
                    __typename
                }
                collectible(id: $collectibleId) @include(if: $hasCollectibleId) @skip(if: $hasListing) {
                    id
                    formattedIssueNumber
                    suggestedPrice
                    ownedByUser
                    showroom {
                    ...ShowroomEntity
                    __typename
                    }
                    openMarketListingId @include(if: $marketEnabled)
                    transactions {
                    edges {
                        node {
                        id
                        createdAt
                        amountGem
                        feeGem
                        amountUsd
                        buyer {
                            id
                            username
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    collectibleType {
                    ...Collectible
                    __typename
                    }
                    __typename
                }
                marketListing(id: $marketListingId) @include(if: $hasListing) {
                    id
                    createdAt
                    status
                    listingType
                    endingAt
                    price: currentPrice
                    currentPrice
                    userBidPosition
                    seller {
                    id
                    username
                    __typename
                    }
                    marketMetadata {
                    totalMarketListings
                    __typename
                    }
                    bids(first: 1) {
                    totalCount
                    edges {
                        node {
                        id
                        createdAt
                        price
                        status
                        bidder {
                            id
                            username
                            avatar {
                            id
                            url
                            __typename
                            }
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    element {
                    ... on Collectible {
                        id
                        formattedIssueNumber
                        suggestedPrice
                        ownedByUser
                        showroom {
                        ...ShowroomEntity
                        __typename
                        }
                        openMarketListingId @include(if: $marketEnabled)
                        collectibleType {
                        ...Collectible
                        __typename
                        }
                        transactions {
                        edges {
                            node {
                            id
                            createdAt
                            amountGem
                            feeGem
                            amountUsd
                            buyer {
                                id
                                username
                                __typename
                            }
                            __typename
                            }
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                }
                fragment StoreBrandRequiredProps on Brand {
                id
                name
                logo: themeLogoImage {
                    id
                    ...LogoMedia
                    __typename
                }
                background: themeBackgroundImage {
                    id
                    ...BackgroundMedia
                    __typename
                }
                mainTheme: _mainTheme {
                    ...BackgroundTheme
                    accentColor
                    contrastColor
                    __typename
                }
                __typename
                }
                fragment BackgroundMedia on Media {
                id
                url
                __typename
                }
                fragment BackgroundTheme on Theme {
                backgroundColor {
                    top
                    bottom
                    __typename
                }
                __typename
                }
                fragment LogoMedia on Media {
                id
                url
                __typename
                }
                fragment StoreSeriesRequiredProps on Series {
                id
                name
                logo: themeLogoImage {
                    ...LogoMedia
                    __typename
                }
                background: themeBackgroundImage {
                    ...BackgroundMedia
                    __typename
                }
                mainTheme: _mainTheme {
                    ...BackgroundTheme
                    accentColor
                    contrastColor
                    __typename
                }
                __typename
                }
                fragment StoreLicensorRequiredProps on Licensor {
                id
                name
                logo: themeLogoImage {
                    id
                    ...LogoMedia
                    __typename
                }
                background: themeBackgroundImage {
                    id
                    ...BackgroundMedia
                    __typename
                }
                mainTheme: _mainTheme {
                    ...BackgroundTheme
                    accentColor
                    contrastColor
                    __typename
                }
                __typename
                }
                fragment ShowroomEntity on Showroom {
                id
                metadata
                showroomType
                ownedByUser
                name
                image {
                    id
                    url
                    direction
                    __typename
                }
                showroomCollectibles {
                    id
                    xPosition
                    yPosition
                    zPosition
                    xRotation
                    yRotation
                    zRotation
                    scale
                    collectible {
                    id
                    ownedByUser
                    formattedIssueNumber
                    collectibleType {
                        id
                        name
                        storePrice
                        rarity
                        totalAvailable
                        totalIssued
                        totalOwnedByUser
                        storeCurrencyType
                        defaultCollectibleShowroomMetadata
                        image {
                        id
                        url
                        direction
                        __typename
                        }
                        IosMedia: iosAsset {
                        id
                        url
                        updatedAt
                        __typename
                        }
                        AndroidMedia: androidAsset {
                        id
                        url
                        updatedAt
                        __typename
                        }
                        showroomBackground: backgroundImage {
                        id
                        url
                        __typename
                        }
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                __typename
                }'''
                collectible_data = {
                "operationName": "CollectibleQuery",
                "variables": {
                    "hasListing": False,
                    "marketListingId": "",
                    "collectibleId": "",
                    "hasCollectibleId": False,
                    "marketEnabled": True
                },
                "query": collectible_data_query
                }
                blindbox_buy_query = '''mutation PlaceStoreReservationForBlindbox($id: ID!) {
                placeBlindboxReservation(elementId: $id) {
                    element {
                    availableReservations
                    id
                    isFree
                    isUnlimited
                    storePrice
                    totalAvailable
                    totalIssued
                    __typename
                    }
                    expiresAt
                    id
                    reserver {
                    id
                    __typename
                    }
                    status
                    __typename
                }
                }'''
                self.blindbox_buy_data = {
                "operationName": "PlaceStoreReservationForBlindbox",
                "variables": {
                },
                "query": blindbox_buy_query
                }
                blindbox_purchase_query = '''mutation StoreBlindBoxPurchaseMutation($id: ID!, $captchaCode: String!, $captchaSiteKey: String!) {
                blindboxPurchase(
                    elementId: $id
                    captchaCode: $captchaCode
                    captchaSiteKey: $captchaSiteKey
                ) {
                    issueNumber
                    transaction {
                        id
                        status
                        buyer {
                        gemBalance
                    __typename
                }
                    }
                    collectibleType {
                        id
                        name
                        storePrice
                        rarity
                        totalAvailable
                        totalIssued
                        editionType
                        totalOwnedByUser
                        storeCurrencyType
                        image {
                        id
                        url
                        direction
                        }
                    }
                    }
                    }'''
                self.blindbox_purchase_data = {
                "operationName": "StoreBlindBoxPurchaseMutation",
                "variables": {
                },
                "query": blindbox_purchase_query
                }
                return
        except:
            logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--VEVE-->')

    class Bot:

        localTasks = {}
        
        def __init__(self):
            self.create_folders()
            
            self.log_file_name = 'logs/'+ str(datetime.today())[:10]+datetime.today().strftime(" %H;%M;%S;%f")[:-4] + '.txt'
            open(self.log_file_name, 'w+').close()
            
            logging.basicConfig(filename=self.log_file_name, encoding='utf-8', level=logging.WARNING)
            logging.getLogger('Bybit').setLevel(logging.INFO)
            logging.getLogger('MeSniper').setLevel(logging.INFO)
            logging.getLogger('FFFSniper').setLevel(logging.INFO)
            logging.getLogger('Bot').setLevel(logging.INFO)

            self.time_pypresence = time.time()
            self.presence('Getting a WL')
            
            self.idTasks = 0
            self.ctoken = []
            
        def start(self):
            self.guard()

        def create_folders(self):
            data = self.open_data()
            try:
                data['rpc']
            except:
                data['rpc'] = {}
                self.save_data(data)
            try:
                data['phantom']
            except:
                data['phantom'] = {}
                self.save_data(data)
            try:
                os.mkdir('collections')
            except:pass

            try:
                os.mkdir('logs')
            except:pass

            try:
                os.mkdir('proxy')
            except:pass

        def create(self):
            data = {
                "key": input("Enter License Key: "),
                "dshook": input("Enter Discord hook: "),
                "captcha": input("1. CapMonster\n2. AntiCaptcha \nEnter service for captcha "),
                "api": {
                    "CapMonster":"",
                    "AntiCaptcha":""
                },
                'phantom':{},
                'rpc':{},
                'cloudTasks':[],
                'proxy':[],
                'token':[], 
                }
            if data['captcha'] == '1':
                data['captcha'] = 'CapMonster'
                data['api']['CapMonster'] = input('Enter CapMonster Api: '+Fore.LIGHTCYAN_EX)
                
                print("\n\033[A \033[A"+Style.RESET_ALL)
            else:
                data['captcha'] = 'AntiCaptcha'
                data['api']['AntiCaptcha'] = input('Enter AntiCaptcha Api: '+Fore.LIGHTCYAN_EX)

                print("\n\033[A \033[A"+Style.RESET_ALL)
            
            open('data.json', 'w').write(json.dumps(data, indent = 4)) 
            
            print(Fore.GREEN + 'save!' + Fore.RESET)
            
            self.start()

        def guard(self):
            # disable guard
            self.menu('main')
            
            session = requests.Session()
            session.get('http://127.0.0.1:8000/csrf')
            
            logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--GUARD-->')
            
            self.csrf = session.cookies.get_dict()['csrftoken']
            self.a = session.get('http://127.0.0.1:8000/a').json()['a']
            self.session = session.cookies.get_dict()['sessionid']
            self.hash = self.shelter(self.a)
            
            self.progress_bar("Authorization ")
            session = requests.Session()
            session.get("http://127.0.0.1:8000/csrf")

            logging.exception("[" + datetime.today().strftime("%H:%M:%S:%f")[:-4] + "]" + "<--GUARD-->")

            self.csrf = session.cookies.get_dict()["csrftoken"]
            self.a = session.get("http://127.0.0.1:8000/a").json()["a"]
            self.session = session.cookies.get_dict()['sessionid']
            self.hash = self.shelter(self.a)
            
            data = self.open_data()
            key = data["key"]
            
            if requests.post("http://127.0.0.1:8000/login", 
                headers = {
                    "key":key, 
                    "X-CSRFToken": self.csrf, 
                    "cookie": f"csrftoken={self.csrf};sessionid={self.session};",
                    "referer": "http://127.0.0.1:8000/"
                },
                json = {
                    "hash": self.hash
                }).json()['status'] == 'success':
                
                self.bar = 'stop'
                time.sleep(1)
                self.menu('main')
            else:
                
                self.bar = 'stop'
                time.sleep(1)
                data['key'] = input('KEY FALSE\nEnter License Key: '+Fore.LIGHTMAGENTA_EX)
                
                print("\n\033[A \033[A"+Style.RESET_ALL)

                self.save_data(data)
                self.guard()

        def shelter(self, alf):
            alfavit = alf
            alfavitShelter = alfavit.copy()
            random.shuffle(alfavitShelter)
            
            a = str(platform.node()[::-1])
            b = str(platform.processor()[::-1])
            
            c = 'Mac = True'[::-1]
            
            shelter1 = ''
            for i in range(len(a)):
                shelter1 = shelter1 + alfavitShelter[alfavit.index(a[i])]
            
            shelter2 = ''
            for i in range(len(b)):
                shelter2 = shelter2 + alfavitShelter[alfavit.index(b[i])]
            
            shelter3 = ''
            for i in range(len(c)):
                shelter3 = shelter3 + alfavitShelter[alfavit.index(c[i])]
                
            alfavitShelter.insert(alfavitShelter.index('1')+1, shelter1)
            alfavitShelter.insert(alfavitShelter.index('2')+1, shelter2)
            alfavitShelter.insert(alfavitShelter.index('3')+1, shelter3)
            
            return alfavitShelter

        def open_data(self):
            try:
                return json.load(open('data.json', 'r'))
            except:
                print(Fore.RED + 'data.json not found' + Fore.RESET)
                
                self.create()

        def save_data(self, data):
            open('data.json', 'w').write(json.dumps(data, indent = 4))

        def progress_bar(self, text):
            spinner = Spinner(Fore.CYAN + text + Fore.RESET)
            self.bar = 'run'
            def run():
                while self.bar != 'stop':
                    time.sleep(0.13)
                    spinner.next()
                print('')
            threading.Thread(target=run, args=()).start()

        def captcha(self, func, sitekey):
            data = self.open_data()
            service = data['captcha']
            self.Api = data['api'][data['captcha']]

            if func == 'change':
                data = self.open_data()
                if service == 'CapMonster':
                    data['captcha'] = 'AntiCaptcha'
                elif service == 'AntiCaptcha':
                    data['captcha'] = 'CapMonster'
                self.save_data(data)
            
            if func == 'api':
                print(Fore.MAGENTA + service + Fore.RESET + ' ' + self.Api)
                try:
                    if service == 'AntiCaptcha':
                        print(Fore.MAGENTA+'Balance '+Fore.RESET+str(AntiCaptchaControl.AntiCaptchaControl(anticaptcha_key = self.Api).get_balance()['balance'])+' $')
                    else:
                        print(Fore.MAGENTA+'Balance '+Fore.RESET+str(requests.post('https://api.capmonster.cloud/getBalance', json={"clientKey":'07392fb59d4efcbcedb1962d9321e283'}).json()['balance'])+' $')
                except:
                    print('Get balance Error')
                
                NewApi = input('New Api: '+Fore.LIGHTMAGENTA_EX)
                print("\n\033[A \033[A"+Style.RESET_ALL)
                
                if NewApi not in [' ','']:
                    data['api'][data['captcha']] = NewApi
                    
                self.save_data(data)

            elif func == 'token':
                if service == 'CapMonster':
                    def getTaskResult(Api, taskId):
                        global taskResult
                        
                        taskResult = requests.post('https://api.capmonster.cloud/getTaskResult',
                            json = {
                                "clientKey": Api,
                                "taskId": taskId
                            }).json()
                        
                        if taskResult['status'] == 'processing':
                            getTaskResult(Api, taskId) 
                            time.sleep(1) 
                        else:
                            self.ctoken.append(taskResult['solution']['gRecaptchaResponse'])
                            return taskResult['solution']['gRecaptchaResponse']
                        
                    def createTask(Api):
                        taskId = requests.post('https://api.capmonster.cloud/createTask',
                            json = {
                                "clientKey": self.Api,
                                "task": {
                                    "type":"HCaptchaTaskProxyless",
                                    "websiteURL":"https://discord.com/login",
                                    "websiteKey": sitekey
                                }
                            }).json()['taskId']
                        
                        getTaskResult(self.Api, taskId)
                        
                    createTask(self.Api)

                elif service == 'AntiCaptcha':
                    ANTICAPTCHA_KEY = self.Api
                    WEB_URL = "https://discord.com/login"
                    SITE_KEY = sitekey
                    
                    result = HCaptchaTaskProxyless.HCaptchaTaskProxyless(
                        anticaptcha_key = ANTICAPTCHA_KEY).captcha_handler(websiteURL = WEB_URL, websiteKey = SITE_KEY)
                    
                    self.ctoken.append(result['solution']['gRecaptchaResponse'])
                    
                    return result['solution']['gRecaptchaResponse']

        def window(self, func, data):
            def get_text():
                global inpt 
                inpt = text.get(1.0, END)
                root.destroy()
            
            def delete_text():
                text.delete(1.0, END)
            
            root = Tk()
            root.title('Infinite AIO')
            root.resizable(height = False, width = False)
            root.configure(background='white')
            text = Text(width=70, height=20)
            text.configure(background='white')
            
            if func == 'del':
                for i in range(len(self.data[data])):
                    if data == 'token':
                        text.insert(1.0, self.data['token'][-i-1] + '\n')
                    elif data == 'proxy':
                        text.insert(1.0, self.data['proxy'][-i-1] + '\n')

            text.pack()
            frame = Frame()
            frame.pack()
            
            Button(frame, text="Save", width=39,
                command=get_text).pack(side=RIGHT)
            
            Button(frame, text="Delete", width=39,
                command=delete_text).pack(side=LEFT)
            
            root.attributes("-topmost", True)
            root.mainloop()
            
            return inpt

        def token(self, func):
            self.data = self.open_data()
            if func == 'add':
                inpt = self.window(func, 'token')
                list = inpt.split('\n')[:-1]
                
                for i in range(len(list)):
                    list[i]
                    self.data['token'].append(list[i])
                
                self.save_data(self.data)
            
            elif func == 'del':
                inpt = self.window(func, 'token')
                list = inpt.split('\n')[:-2]
                
                for i in range(len(list)):
                    list[i]
                
                self.data['token'] = list
                self.save_data(self.data)
            
            elif func == 'get':
                data = self.open_data()
                self.progress_bar('Captcha token generate ')
                self.ctoken.clear()
                
                try:
                    token = self.captcha('token', 'f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34')
                except:
                    self.bar = 'stop'
                    time.sleep(0.25)
                    input('Capthca error')
                    return
            
                self.bar = 'stop'
                time.sleep(0.25)
                session = requests.Session()
                json = {
                    "captcha_key": self.ctoken[0],
                    "login": '%s' %input('Login '),
                    "password": '%s' %input('Pass ')
                    }
                
                r = session.post('https://discord.com/api/v9/auth/login', json=json).json()
                self.ctoken.clear()
                
                try:
                    if(r['token'] != None):
                        print('Successeful login - ' + r['token'])
                        data['token'].append(r['token'])
                        self.save_data(data)
                        input('Save. Press enter')
                except:
                    logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--TOKEN-->')
                    input('Error. Press enter')
                
            elif func == 'open':
                data = self.open_data()
                
                for i in range(len(data['token'])):
                    print(i + 1, data['token'][i])
                token = str(data['token'][int(input('Number token '+Fore.LIGHTMAGENTA_EX)) - 1])
                print("\n\033[A \033[A"+Style.RESET_ALL)
                
                for i in range(len(data['proxy'])):
                    print(i + 1, data['proxy'][i])
                proxy = self.proxy(str(data['proxy'][int(input('Number proxy '+Fore.LIGHTMAGENTA_EX)) - 1]))
                print("\n\033[A \033[A"+Style.RESET_ALL)
                
                options = {
                    'disable_capture': True,
                    'auto_config': True, 
                    'proxy': {
                        'http': 'http://' + proxy,
                        'https': 'https://' + proxy,
                        'no_proxy': 'localhost,127.0.0.1'
                    }
                }
                
                chromedriver_autoinstaller.install()
                chrome_options = webdriver.ChromeOptions()
                chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
                
                driver = webdriver.Chrome(options=chrome_options, seleniumwire_options=options)
                driver.get('https://2ip.ru')
                
                if input(Fore.BLUE + 'NEXT ' + Fore.RESET) == 'EXIT':
                    driver.quit()
                    
                driver.get('https://discord.com/login')
                driver.execute_script('''
                    let token = "%s";
                    function login(token) {
                        setInterval(() => {
                        document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${token}"`
                        }, 50);
                        setTimeout(() => {
                        location.reload();
                        }, 2500);
                    }
                    login(token);
                '''%(token))
                
                input(Fore.RED + 'EXIT ' + Fore.BLUE)
                
                driver.quit()

        def proxy(self, func):
            if ':' in func:
                try:
                    return (func.split(':')[2] + ':' + func.split(':')[3] + '@' + func.split(':')[0] + ':' + func.split(':')[1])
                except:
                    return "PROXY ERROR"
            
            elif func == 'add':
                self.data = self.open_data()
                
                inpt = self.window(func, 'proxy')
                list = inpt.split('\n')[:-1]
                
                for i in range(len(list)):
                    self.data['proxy'].append(list[i])
                
                self.save_data(self.data)
            
            elif func == 'del':
                self.data = self.open_data()
                
                inpt = self.window(func, 'proxy')
                list = inpt.split('\n')[:-2]
                
                self.data['proxy'] = list
                self.save_data(self.data)
                
            elif func == 'create_proxylist':
                inpt = self.window('add', 'proxy')
                
                open('proxy/'+str(input('Proxy list name '))+'.txt', 'w+').write(inpt.strip())

            elif func == 'test':
                workProxy = []
                dontWorkProxy = []

                delete = input('Delete dont work proxy? (y/n) '+Fore.LIGHTMAGENTA_EX)
                print("\n\033[A \033[A"+Style.RESET_ALL)
                
                data = self.open_data()
                proxy = data['proxy']
                
                for i in range(len(proxy)):
                    proxies = {
                        'http':'http://' + self.proxy(str(proxy[i]))
                    }
                    
                    try:
                        response = requests.get('http://myip.ru/', proxies=proxies)
                        if response.status_code == 200:
                            workProxy.append(proxy[i])
                            print(Fore.GREEN + 'OK' + Fore.RESET)
                    except:
                        print(Fore.RED + 'ERROR' + Fore.RESET)
                        dontWorkProxy.append(proxy[i])
                    
                if delete == 'y':
                    data['proxy'] = workProxy
                    self.save_data(data)
                else:
                    print('Dont work proxy' , dontWorkProxy)
                
                input('Ready. Press enter')

#       <----------------------DISCORD--------------------->
        def presence(self, text):
            try:
                RPC = Presence("958624126136905759")
                RPC.connect()
                RPC.update(
                    state="v1.1.3",
                    details=text,
                    large_image="https://media.discordapp.net/attachments/815275144892383292/979387392865730570/infinite1-1-8_8.png",
                    start=self.time_pypresence
                )
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + ' <--PRESENCE-->')

        def dshook(self, func):
            try:
                if func == 'change':
                    data = self.open_data()
                    
                    if data['dshook'] != '':
                        print(Fore.MAGENTA + data['dshook'] + Fore.RESET)
                    
                    hook = input('Dshook '+Fore.LIGHTCYAN_EX)
                    print("\n\033[A \033[A"+Style.RESET_ALL)

                    if hook not in [' ', '']:
                        data['dshook'] = hook

                    self.save_data(data)
                    
                    hook = Webhook(
                        data['dshook'],
                        username='Infinite',
                        avatar_url='https://media.discordapp.net/attachments/967039935058165800/974392751279976528/infinite1-1.png'
                    )
                    
                    hook.execute('WORK!')
                    
                elif func == 'get':
                    data = self.open_data()
                    
                    return data['dshook']
                
                elif func == 'create':
                    data = self.open_data()
                    hook = Webhook(
                        'https://discord.com/api/webhooks/955452395897376868/a_C2Tz7zYfARMlzeKGqLMhQ02TjBwLyhAoutVX0433_ENo3JBCnSciVOFOsstH7ckNd5',
                        username='Infinite',
                        avatar_url='https://media.discordapp.net/attachments/967039935058165800/974392751279976528/infinite1-1.png'
                    )
                    
                    hook.execute('Create ' + data['key'])
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + ' <--dshook-->')

#       <------------------DISCORD MODULE------------------>
        def HypeSquad(self, tokens, proxie, delay):
            try:
                if len(tokens) % len(proxie) == 0:
                    switchProxy = len(tokens) / len(proxie)
                else:switchProxy = len(tokens) // len(proxie) + 1
                
                proxyID = 0
                ua = UserAgent()
                
                for i in range(len(tokens)):
                    proxies = {
                        'http':'https://' + str(self.proxy(str(proxie[proxyID])))
                    }
                    headers = {
                        'authorization': tokens[i],
                        'content-type': 'application/json',
                        'user-agent': ua.chrome,
                        'origin': 'https://discord.com',
                        'referer': 'https://discord.com/channels/@me'
                    }
                    
                    data = '{"house_id":%s}'%(random.randint(1,3))
                    response = requests.post('https://discord.com/api/v9/hypesquad/online', headers=headers, data=data, proxies=proxies)
                    if response.status_code ==  204:
                        print(Fore.GREEN + 'SUCCESS' + Fore.RESET)
                    else: 
                        print(Fore.YELLOW + 'ERROR' + Fore.RESET)
                    
                    if (i + 1) / switchProxy == 1 or ((i + 1) / switchProxy) % 2 == 0:
                        proxyID += 1
                    
                    time.sleep(int(delay))
                
                return (Fore.GREEN + 'END' + Fore.RESET)
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--HYPESQUAD-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def change_nickname(self, token, proxy, nick, password):
            try:
                ua = UserAgent()
                proxies = {
                    'http':'https://' + self.proxy(str(proxy))
                }
                headers = {
                    'authorization': token,
                    'content-type': 'application/json',
                    'user-agent': ua.chrome,
                    'origin': 'https://discord.com',
                    'referer': 'https://discord.com/channels/@me'
                }
                
                data = '{"username":"%s","password":"%s"}'%(nick, password)
                response = requests.patch('https://discord.com/api/v9/users/@me', headers=headers, data=data, proxies=proxies)
                if response.status_code == 200:
                    print(Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else:
                    print(Fore.GREEN + 'ERROR' + Fore.RESET)
                
                return (Fore.GREEN + 'END' + Fore.RESET)
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--CHANGE_NICKNAME-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def change_avatar(self, tokens, proxie, link, delay): 
            try:
                if len(tokens) % len(proxie) == 0:
                    switchProxy = len(tokens) / len(proxie)
                else:switchProxy = len(tokens) // len(proxie) + 1
                
                proxyID = 0
                ua = UserAgent()
                for i in range(len(tokens)):
                    if link == '':
                        photo = requests.get('https://picsum.photos/200/200')
                    else:
                        photo = requests.get(link)

                    encoded_image = base64.b64encode(photo.content).decode('utf-8')
                    
                    proxies = {
                        'http':'http://' + self.proxy(str(proxie[proxyID]))
                    }
                    headers = {
                        'authorization': tokens[i],
                        'content-type': 'application/json',
                        'user-agent': ua.chrome,
                        'origin': 'https://discord.com',
                        'referer': 'https://discord.com/channels/@me'
                    }
                    data = '{"avatar":"data:image/png;base64,%s"}'%(encoded_image)
                    response = requests.patch('https://discord.com/api/v9/users/@me', headers=headers, data=data, proxies=proxies)
                    
                    try:
                        print(Fore.GREEN + response.json()['username'] + Fore.RESET + ' - Change avatar DONE!')
                    except:
                        try:
                            print(Fore.RED + response.json()['message'] + Fore.RESET)
                        except:
                            print(Fore.YELLOW + 'ERROR' + Fore.RESET)
                    
                    if (i + 1) / switchProxy == 1 or ((i + 1) / switchProxy) % 2 == 0:
                        proxyID += 1
                        
                    time.sleep(int(delay))
                
                return 'END'
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--CHANGE_AVATAR-->')
                return 'Error. Check Logs'

        def solo_bumper(self, message, token, link, delay, proxy):
            try:
                data = self.open_data()
                key = data['key']
                task_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '|' + key

                response = requests.post('http://127.0.0.1:8000/createTasks',
                    headers = {
                        "task": "messageBumper",
                        "mode": "soloBumper",
                        "X-CSRFToken": self.csrf,
                        'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                        "key": key,
                        'referer': 'http://127.0.0.1:8000/',
                        'task-id': task_id,
                        'lang': 'RU'
                    },
                    json = {
                        "messages": message,
                        "token": token,
                        "link": link,
                        "delay": delay,
                        'hash': random.shuffle(self.hash),
                        "proxy": self.proxy(proxy),
                        'dshook':self.dshook('get'),
                        
                    }
                )
                
                if response.json()['status'] == 'success':
                    data = self.open_data()
                    data['cloudTasks'].append(task_id)
                    self.save_data(data)
                    return (Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else: return (Fore.RED + 'ERROR' + Fore.RESET)
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--SOLO_BUMPER-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def delete_bumper(self, message, token, link, delay, proxy):
            try:
                data = self.open_data()
                key = data['key']
                task_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '|' + key
                
                response = requests.post('http://127.0.0.1:8000/createTasks',
                    headers = {
                        "task": "messageBumper",
                        "mode": "deleteBumper",
                        "X-CSRFToken": self.csrf,
                        'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                        "key": key,
                        'referer': 'http://127.0.0.1:8000/',
                        "task-id": task_id,
                        'lang': 'RU' 
                    },
                    json = {
                        "message": message,
                        "token": token,
                        "link": link,
                        "delay": delay,
                        'hash': random.shuffle(self.hash),
                        "proxy": self.proxy(proxy),
                        'dshook':self.dshook('get')
                    }
                )
                
                if response.json()['status'] == 'success':
                    data = self.open_data()
                    data['cloudTasks'].append(task_id)
                    self.save_data(data)
                    return (Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else: return (Fore.RED + 'ERROR' + Fore.RESET)
            except: 
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--DELETE_BUMPER-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def duo_bumper(self, message1, message2, token1, token2, proxy1, proxy2, link, delay):
            try:
                data = self.open_data()
                key = data['key']
                task_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '|' + key
                
                response = requests.post('http://127.0.0.1:8000/createTasks',
                    headers = {
                        "task": "messageBumper",
                        "mode": "duoBumper",
                        "X-CSRFToken": self.csrf,
                        'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                        "task-id":task_id,
                        'referer': 'http://127.0.0.1:8000/',
                        "key": key,
                        'lang': 'RU'
                        
                    },
                    json = {
                        "messages_first": message1,
                        "messages_second": message2,
                        "token_first": token1,
                        "token_second": token2,
                        "link": link,
                        "delay": delay,
                        'proxy':self.proxy(proxy1) + ';' + self.proxy(proxy2),
                        'dshook':self.dshook('get'),
                        'hash': random.shuffle(self.hash),
                    }
                )
                
                if response.json()['status'] == 'success':
                    data = self.open_data()
                    data['cloudTasks'].append(task_id)
                    
                    self.save_data(data)
                    
                    return (Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else: return (Fore.RED + 'ERROR' + Fore.RESET)
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--DUO_BUMPER-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def ai_mode(self, token1, token2, proxy1, proxy2, link, delay, lang):
            try:
                data = self.open_data()
                key = data['key']
                task_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '|' + key
                
                response = requests.post('http://127.0.0.1:8000/createTasks',
                    headers = {
                        "task": "messageBumper",
                        "mode": "duoBumper",
                        "X-CSRFToken": self.csrf,
                        'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                        "task-id":task_id,
                        'referer': 'http://127.0.0.1:8000/',
                        "key": key,
                        'lang': lang
                        
                    },
                    json = {
                        "messages_first": 'No',
                        "messages_second": 'No',
                        "token_first": token1,
                        "token_second": token2,
                        "link": link,
                        "delay": delay,
                        'proxy': self.proxy(proxy1) + ';' + self.proxy(proxy2),
                        'dshook':self.dshook('get'),
                        'hash': random.shuffle(self.hash),
                    }
                )
                
                if response.json()['status'] == 'success':
                    data = self.open_data()
                    data['cloudTasks'].append(task_id)
                    self.save_data(data)
                    
                    return (Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else: return (Fore.RED + 'ERROR' + Fore.RESET)
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--AI_MODE-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def helper(self, token, proxy, link, delay, lang):
            try:
                data = self.open_data()
                key = data['key']
                task_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '|' + key

                response = requests.post('http://127.0.0.1:8000/createTasks',
                    headers = {
                        "task": "messageBumper",
                        "mode": "soloBumper",
                        "X-CSRFToken": self.csrf,
                        'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                        "key": key,
                        'referer': 'http://127.0.0.1:8000/',
                        'task-id': task_id,
                        'lang': lang
                    },
                    json = {
                        "messages": 'No',
                        "token": token,
                        "link": link,
                        "delay": delay,
                        'hash': random.shuffle(self.hash),
                        "proxy": self.proxy(proxy),
                        'dshook':self.dshook('get'),
                        
                    }
                )
                if response.json()['status'] == 'success':
                    data = self.open_data()
                    data['cloudTasks'].append(task_id)
                    self.save_data(data)
                    
                    return (Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else:
                    return (Fore.RED + 'ERROR' + Fore.RESET)
            except: 
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--HELPER_MODE-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def giveaway(self, tokens, reaction, id_giveaway, id_channel, proxies):
            try:
                data = self.open_data()
                key = data['key']
                
                if len(tokens) % len(proxies) == 0:
                    switchProxy = len(tokens) / len(proxies)
                else:switchProxy = len(tokens) // len(proxies) + 1
                
                proxyID = 0
                
                for i in range(len(tokens)):
                    response = requests.post('http://infinite-parser.ru/Giveaway',
                        headers = {
                            "task": "giveaway",
                            "X-CSRFToken": self.csrf,
                            'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                            'referer': 'http://127.0.0.1:8000/',
                            'key':key,
                        },
                        json = {
                            'tokens': tokens[i],
                            'reaction': reaction,
                            'id_giveaway': id_giveaway,
                            'id_channel': id_channel,
                            'proxy': self.proxy(proxies[proxyID]),
                        })
                    
                    try:
                        if response.json()['status'] == 'SUCCESS':
                            print(tokens[i] +' '+ Fore.GREEN + response.json()['status'] + Fore.RESET)
                        else:
                            print(tokens[i] +' '+Fore.RED + response.json()['status'] + Fore.RESET)
                    except:
                        print(tokens[i] + Fore.RED + 'ERROR. Logs' + Fore.RESET)
                        logging.getLogger('Bot').info('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + '] <--GIVEAWAY-->\n' + tokens[i] + ' - ' + str(response.text))
                    
                    if (i + 1) / switchProxy == 1 or ((i + 1) / switchProxy) % 2 == 0:
                        proxyID += 1
                    
                    return 'END'
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--GIVEAWAY-->')
                return 'ERROR'

        def invite_joiner(self, tokens, proxies, invite_code, rules, emoji, message_id, verification_channel, code, referral_channel, delay, indexs, ctoken):
            try:
                if len(tokens) % len(proxies) == 0:
                    switchProxy = len(tokens) / len(proxies)
                else:switchProxy = len(tokens) // len(proxies) + 1
                
                data = self.open_data()
                key = data['key']
                
                proxyID = 0
                
                for i in range(len(tokens)):
                    response = requests.post('http://127.0.0.1:8000/createTasks',
                        headers = {
                            "task": "claimInvites",
                            "X-CSRFToken": self.csrf,
                            'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                            'referer': 'http://127.0.0.1:8000/',
                            'key':key,
                        },
                        json = {
                            "token": tokens[i],
                            "invite_code": invite_code,
                            "rules": rules,
                            "code": code,
                            "emoji": emoji,
                            'proxy':self.proxy(proxies[proxyID]),
                            "message_id": message_id,
                            "verification_channel": verification_channel,
                            "referral_channel": referral_channel,
                            "delay": delay,
                            'hash': random.shuffle(self.hash),
                            'dshook':self.dshook('get'),
                            'ctoken': ctoken[i]
                        })
                    
                    try:
                        if response.json()['response'] == 'SUCCESS':
                            print(tokens[i] + ' - ' + Fore.GREEN + response.json()['response'] + Fore.RESET)
                        else:
                            print(tokens[i] + ' - ' + Fore.RED + response.json()['response'] + Fore.RESET)
                        
                        if (i + 1) / switchProxy == 1 or ((i + 1) / switchProxy) % 2 == 0:
                            proxyID += 1
                    except:
                        print(tokens[i] + ' - ' + Fore.RED + 'ERROR. Logs' + Fore.RESET)
                        logging.getLogger('Bot').info('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + '] <--INVITE_JOINER-->' + str(response.text))
                
                self.responseCreateTask = 'END'
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--INVITE_JOINER-->')
                self.responseCreateTask = 'ERROR'

        def invite_monitor(self, token, proxy, channelID, nameTask):
            try:
                data = self.open_data()
                key = data['key']
                task_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '|' + key
                channelID = str(channelID)
                
                response = requests.post('http://127.0.0.1:8000/createTasks',
                    headers={
                        'task':'inviteMonitor',
                        "X-CSRFToken": self.csrf,
                        'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                        "task-id":task_id,
                        'referer': 'http://127.0.0.1:8000/',
                        'name': nameTask,
                        "key": key
                    },
                    json = {
                        'channel_id':channelID,
                        'token':token,
                        'proxy':self.proxy(proxy),
                        'dshook':self.dshook('get'),
                        'hash': random.shuffle(self.hash),
                    })

                if response.json()['status'] == 'success':
                    data = self.open_data()
                    data['cloudTasks'].append(task_id)
                    self.save_data(data)
                
                    return (Fore.GREEN + 'SUCCESS' + Fore.RESET)
                else: return (Fore.RED + 'ERROR' + Fore.RESET)
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--INVITE_MONITOR-->')
                return (Fore.RED + 'ERROR' + Fore.RESET)

        def check_count_messages(self, tokens, proxies, server):
            try:
                self.progress_bar('Check ')
                
                if len(tokens) % len(proxies) == 0:
                    switchProxy = len(tokens) / len(proxies)
                else:switchProxy = len(tokens) // len(proxies) + 1
                
                table = []
                proxyID = 0
                
                for i in range(len(tokens)):
                    table.append(Discord().get_count_messages(tokens[i], proxies[proxyID], server))
                    
                    if (i + 1) / switchProxy == 1 or ((i + 1) / switchProxy) % 2 == 0:
                        proxyID += 1

                self.bar = 'stop'
                time.sleep(1)
                print(tabulate(table, ['Nick', 'Result'], tablefmt="pretty"))

                return 'END'
            except:
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--MESSAGES_COUNT-->')
                return 'Error. Check Logs'

        def check_token(self, tokens, proxies):
            try:
                data = self.open_data()
                
                print(Fore.LIGHTCYAN_EX+'--------'+Fore.RESET)

                if len(tokens) % len(proxies) == 0:
                    switchProxy = len(tokens) / len(proxies)
                else:switchProxy = len(tokens) // len(proxies) + 1

                proxyID = 0
                d = 0

                for i in range(len(tokens)):
                    result = Discord().get_user(tokens[i], proxies[proxyID])

                    if result == 'Error get user':
                        data['token'].pop(i-d)
                        d += 1
                        print(Fore.RED+result+Fore.RESET)
                    else:
                        print(Fore.GREEN+result+Fore.RESET)
                    
                    if (i + 1) / switchProxy == 1 or ((i + 1) / switchProxy) % 2 == 0:
                        proxyID += 1
                
                self.save_data(data)

                return 'END'
            except:
                self.save_data(data)
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--CHECK_TOKEN-->')

                return 'Error. Check Logs'

#       <-----------------------CLI---------------------->
        def tasks_display(self):
            self.logo()
            
            print(self.localTasks)

            data = self.open_data()
            if len(data['cloudTasks']) != 0:
                print(Fore.YELLOW + 'Cloud Tasks:' + Fore.RESET)
                
                for i in range (len(data['cloudTasks'])):
                    try:
                        response = requests.post('http://127.0.0.1:8000/getTasks',
                            headers = {
                                "X-CSRFToken": self.csrf,
                                'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                                'referer': 'http://127.0.0.1:8000/',
                            },
                            json = [data['cloudTasks'][i]]
                        )
                        
                        task_info = json.loads(list(response.json()['tasks'].values())[0].replace("'",'"'))

                        if task_info[2] == 'END':
                            status = Fore.YELLOW + str(task_info[2]) + Fore.RESET
                        elif task_info[2] == 'OK':
                            status = Fore.GREEN + str(task_info[2]) + Fore.RESET
                        else: status = Fore.RED +str(task_info[2])+ Fore.RESET

                        print(str(i + 1) + '.' + Fore.CYAN +' Name:' + Fore.RESET + task_info[3] + Fore.CYAN + '  Mode:'+ Fore.RESET + task_info[1] + Fore.CYAN + '  Server:' + Fore.RESET + task_info[4] + Fore.CYAN + '  Status:' + status)
                    except:
                        try:
                            if task_info[2] == 'END':
                                status = Fore.YELLOW + 'END' + Fore.RESET
                            elif task_info[2] == 'OK':
                                status = Fore.GREEN + 'OK' + Fore.RESET
                            else: status = Fore.RED + str(task_info[2]) + Fore.RESET
                            print(str(i + 1) + '.' + Fore.CYAN +' Name:' + Fore.RESET + task_info[0] + Fore.CYAN + '  Mode:'+ Fore.RESET + task_info[1] + Fore.CYAN + '  Status:' +Fore.RESET +  status)
                        except:
                            logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--TASK_DISPLAY-->')
                            print(str(i + 1) + '.' + Fore.RED + ' Task Not Found' + Fore.RESET)  
                        
                        logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--TASK DISPLAY-->')
            if len(self.localTasks) != 0:
                print(Fore.YELLOW + 'Local Tasks:' + Fore.RESET)

                for i in self.localTasks:
                    info = self.localTasks[i]
                    if info['status'] == 'STOP':
                        return
                    
                    B = Fore.CYAN
                    R = Fore.RESET

                    print(info['task_id'] + '.' + B + ' Mode:' + R + (info['mode'] + '     ')[:6] + B + ' Product:' + R + (info['product'] + '     ')[:6] + B + ' Proxy:' + R + (info['proxy'] + '     ')[:5] + B + ' Timer:' + R + (info['time'] + '     ')[:11] + B + ' Cd ' + R + (info['cooldown'] + '     ')[:4]  + B + ' Status:' + R + info['status'])
            
            inpt = input('> '+Fore.LIGHTCYAN_EX)
            print("\n\033[A \033[A"+Style.RESET_ALL)

            try:
                print(self.localTasks[int(inpt)]['logs'][0])
                self.logo()
                print(B + 'Task:'+ str(inpt) + R)

                for i in range(len(self.localTasks[int(inpt)]['logs'])):
                    print('>', self.localTasks[int(inpt)]['logs'][i])
                
                input('')
                self.tasks_display()
            except:
                pass

            if inpt == 'del':
                if len(data['cloudTasks']) == 0 and len(self.localTasks) != 0:
                    delete = input('ID ').strip().split(' ')
                    print("\n\033[A \033[A"+Style.RESET_ALL)
                    
                    for i in range(len(delete)):
                        self.localTasks[int(delete[i])]['status'] = 'STOP'
                elif len(data['cloudTasks']) != 0 and len(self.localTasks) == 0:
                    delete = input('ID ').strip().split(' ')
                    self.delete_tasks(delete)
                else:
                    type = input('1. Cloud\n2. Local\n> '+Fore.LIGHTCYAN_EX)
                    print("\n\033[A \033[A"+Style.RESET_ALL)
                    
                    if type == '1':
                        delete = input('ID '+Fore.LIGHTCYAN_EX).strip().split(' ')
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        self.delete_tasks(delete)
                    elif type == '2':
                        delete = input('ID '+Fore.LIGHTCYAN_EX).strip().split(' ')
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        for i in range(len(delete)):
                            self.localTasks[int(delete[i])]['status'] = 'STOP'
                
                self.tasks_display()
            elif inpt == '':
                self.tasks_display()

        def delete_tasks(self, delete):
            task_id = []
            remove = {}
            
            data = self.open_data()
            for i in range(len(delete)):
                task_id.append(data['cloudTasks'][int(delete[i]) - 1])
            
            remove['delete'] = task_id
            response = requests.post('http://127.0.0.1:8000/deleteTasks',
                headers = {
                    "X-CSRFToken": self.csrf,
                    'cookie': 'csrftoken='+self.csrf+';sessionid='+self.session+';',
                    'referer': 'http://127.0.0.1:8000/',
                },
                json = remove
            )
            
            if response.json()['status'] != 'success':
                input('Error')
            
            index = 0
            
            for i in range(len(delete)):
                data['cloudTasks'].pop(int(delete[i]) - 1 - index)
                index += 1

            self.save_data(data)

        def menu(self, select):
            self.logo()
            data = self.open_data()

            if select == 'main':
                print('1. Tasks' + Fore.MAGENTA, len(data['cloudTasks']) + len(self.localTasks), Fore.RESET + '\n2. Create tasks\n3. User data')

            elif select == 'create':
                print('1. Message bumper\n2. Invite joiner\n3. Invite monitor\n4. Bybit\n5. ME Sniper\n6. FFF Sniper\n7. Giveaway\n8. Veve')

            elif select == 'data':
                print('1. Token' + Fore.MAGENTA , len(data['token']) , Fore.RESET + '\n2. Proxy' + Fore.MAGENTA , len(data['proxy']) , Fore.RESET + '\n3. Captcha' + Fore.MAGENTA, data['captcha'], Fore.RESET + '\n4. Discord hook\n5. RPC ' + Fore.MAGENTA + str(len(data['rpc'])) + Fore.RESET+'\n'+'6. Phantom ' + Fore.MAGENTA + str(len(data['phantom'])) + Fore.RESET)

            elif select == 'token':
                print('1. Add token\n2. Get token\n3. Open token\n4. Delete token\n5. Improvement\n6. Message count\n7. Check token')
            
            elif select == 'proxy':
                print('1. Add proxy\n2. Test proxy\n3. Delete proxy\n4. Create proxylist')
            
            self.cli(select)

        def logo(self):
            os.system('clear')
            print(Fore.LIGHTMAGENTA_EX + '''
  __    __   __    ______   __    __   __    __    ______   ______    
 /\ \  /\ "-.\ \  /\  ___\ /\ \  /\ "-.\ \  /\ \  /\__  _\ /\  ___\   
 \ \ \ \ \ \-.  \ \ \  __\ \ \ \ \ \ \-.  \ \ \ \ \/_/\ \/ \ \  __\ 
  \ \_\ \ \_\ \"\_\ \ \_\    \ \_\ \ \_\ \"\_\ \ \_\   \ \_\  \ \_____\ 
   \/_/  \/_/ \/_/  \/_/     \/_/  \/_/ \/_/  \/_/    \/_/   \/_____/
    ''' + Fore.RESET)

        def cli(self, page):
            try:
                select = input('> '+Fore.LIGHTMAGENTA_EX)
                print("\n\033[A \033[A"+Style.RESET_ALL)
                if page == 'main':
                    if select == '1':
                        self.tasks_display()
                    elif select == '2':
                        self.menu('create')
                    elif select == '3':
                        self.menu('data')
                    elif select == 'git':
                        webbrowser.open('https://infinite-aio.gitbook.io/infinite-aio/', new=2)
                    elif select == 'version':
                        input('1.1.3 ')
                    elif select == 'cls':
                        for i in glob.glob('logs/*'):
                            try:
                                if i == self.log_file_name:
                                    continue
                                os.remove(i)
                            except:pass

                elif page == 'create':
                    if select == '1':
                        mode = input('1. Pair mode\n2. Solo mode\n3. AI mode\n4. Helper mode\n> '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        if mode == '1':
                            data = self.open_data()
                            
                            for i in range(len(data['token'])):
                                print(i + 1, data['token'][i])
                            
                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            
                            token1 = data['token'][int(input('Number 1 token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            proxy1 = data['proxy'][int(input('Number 1 proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            
                            token2 = data['token'][int(input('Number 2 token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            proxy2 = data['proxy'][int(input('Number 2 proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            
                            link = input('Link channel '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            delay = int(input('Delay '+Fore.LIGHTMAGENTA_EX))
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            message = self.window('','').split('\n')[:-1]
                            index = 0
                            message1 = []
                            message2 = []
                            
                            while index != -1:
                                try:
                                    message1.append(message[index])
                                    message2.append(message[index + 1])
                                    index += 2
                                except: index = -1
                            
                            input(self.duo_bumper(message1, message2, token1, token2, proxy1, proxy2, link, delay))

                        elif mode == '2':
                            data = self.open_data()
                            
                            for i in range(len(data['token'])):
                                print(i + 1, data['token'][i])
                            token = data['token'][int(input('Number token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            proxy = data['proxy'][int(input('Number proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            link = input('Link channel '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            delay = int(input('Delay '+Fore.LIGHTMAGENTA_EX))
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            if input('Delete message (y/n)? '+Fore.LIGHTMAGENTA_EX) == 'y':
                                print("\n\033[A \033[A"+Style.RESET_ALL)
                                message = input('Message '+Fore.LIGHTMAGENTA_EX)
                                print("\n\033[A \033[A"+Style.RESET_ALL)
                                
                                input(self.delete_bumper(message, token, link, delay, proxy))
                            else:
                                print("\n\033[A \033[A"+Style.RESET_ALL)
                                message = self.window('','').split('\n')[:-1]
                                
                                input(self.solo_bumper(message, token, link, delay, proxy))

                        elif mode == '3':
                            data = self.open_data()
                            
                            print(Fore.LIGHTCYAN_EX+'-Tokens-'+Fore.RESET)
                            for i in range(len(data['token'])):
                                print(i + 1, data['token'][i])
                            
                            print(Fore.LIGHTCYAN_EX+'-Proxies-'+Fore.RESET)
                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            
                            token1 = data['token'][int(input('Number 1 token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            proxy1 = data['proxy'][int(input('Number 1 proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            token2 = data['token'][int(input('Number 2 token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            proxy2 = data['proxy'][int(input('Number 2 proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            link = input('Link channel '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            delay = int(input('Delay '+Fore.LIGHTMAGENTA_EX))
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            lang = input('Language RU/EN ')
                            
                            if lang == 'RU':
                                lang = 'RU'
                            elif lang == 'EN':
                                lang = 'EN'
                            else:
                                input(Fore.RED + 'ERROR LANG' + Fore.RESET)
                                
                                return

                            input(self.ai_mode(token1, token2, proxy1, proxy2, link, delay, lang))

                        elif mode == '4':
                            data = self.open_data()
                            
                            for i in range(len(data['token'])):
                                print(i + 1, data['token'][i])
                            token = data['token'][int(input('Number token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            proxy = data['proxy'][int(input('Number proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            link = input('Link channel '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            delay = int(input('Delay '+Fore.LIGHTMAGENTA_EX))
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            lang = input('Language RU/EN '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            if lang == 'RU':
                                lang = 'RU'
                            elif lang == 'EN':
                                lang = 'EN'
                            else:
                                input(Fore.RED + 'ERROR LANG' + Fore.RESET)

                                return
                            
                            input(self.helper(token, proxy, link, delay, lang))

                    elif select == '2':
                        invite = input('Invite code '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        
                        if input('Confirm rules (y/n)? '+Fore.LIGHTMAGENTA_EX) == 'y':
                            rules = 'Yes'
                        else: rules = 'No'
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        emoji = input('Emoji ')
                        if emoji not in ['n', '', ' ']:
                            messageID = input('ID message '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            verifyChannel = input('ID verify channel '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                        else: emoji = 'No'; messageID = 'No';verifyChannel = 'No'

                        code = input('Code '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        if code not in ['n', '', ' ']:
                            referral_channel = input('ID Referral channel '+Fore.LIGHTMAGENTA_EX)
                        else: code = 'No'; referral_channel = 'No'
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        data = self.open_data()
                        for i in range(len(data['token'])):
                            print(str(i + 1) + ' ' + data['token'][i])
                        token = input('Numbers Tokens '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        indexs = token.copy()
                        for i in range(len(indexs)):
                            indexs[i] = int(indexs[i]) - 1
                        tokens = []
                        for i in range(len(token)):
                            tokens.append(data['token'][int(token[i]) - 1])
                        
                        for i in range(len(data['proxy'])):
                            print(i + 1, data['proxy'][i])
                        proxy = input('Numbers proxies '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        proxies = []
                        for i in range(len(proxy)):
                            proxies.append(data['proxy'][int(proxy[i]) - 1])
                        
                        delay = input('Delay '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        self.progress_bar('Captcha token generate ')
                        self.ctoken.clear()

                        for i in range(len(tokens)):
                            threading.Thread(target=self.captcha, args=('token', '4c672d35-0701-42b2-88c3-78380b0db560')).start()

                        err = 0
                        while len(self.ctoken) < len(tokens):
                            if err == 10:
                                for i in range(len(tokens) - len(self.ctoken)):
                                    threading.Thread(target=self.captcha, args=('token', '4c672d35-0701-42b2-88c3-78380b0db560')).start()
                                
                                err = 0
                            else:
                                err += 1
                            time.sleep(3)

                        self.bar = 'stop'
                        time.sleep(0.25)
                        self.invite_joiner(tokens, proxies, invite, rules, emoji, messageID, verifyChannel, code, referral_channel, delay, indexs, self.ctoken)
                        self.ctoken.clear()

                        input(self.responseCreateTask + '. Press enter ')

                    elif select == '3':
                        data = self.open_data()
                        
                        for i in range(len(data['token'])):
                            print(i + 1, data['token'][i])
                        token = data['token'][int(input('Number token '+Fore.LIGHTMAGENTA_EX)) - 1]
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        for i in range(len(data['proxy'])):
                            print(i + 1, data['proxy'][i])
                        proxy = data['proxy'][int(input('Number proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        channel_id = input('Channel ID '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        name_task = input('Name task '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        input(self.invite_monitor(token, proxy, channel_id, name_task))

                    elif select == '4':
                        data = self.open_data()
                        
                        usertoken = input('UserToken '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        userAgent = input('UserAgent '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        for i in range(len(data['proxy'])):
                            print(i + 1, data['proxy'][i])
                        proxy_id = input('Number proxy '+Fore.LIGHTMAGENTA_EX).strip()
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        proxy = self.proxy(data['proxy'][int(proxy_id) - 1])
                        id = int(input('ID '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        timer = input('Time '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        self.idTasks += 1

                        self.localTasks[self.idTasks] = {'task_id':str(self.idTasks), 'mode':'Bybit', 'product':str(id), 'proxy':proxy_id, 'time':timer, 'cooldown':'0', 'status':'Create', 'logs':[]}
                        threading.Thread(target=Bybit, args=(usertoken, userAgent, id, proxy, timer, self.idTasks, data['dshook'], data['api']['AntiCaptcha'])).start()

                        input(Fore.GREEN + 'SUCCESS' + Fore.RESET)

                    elif select == '5':
                        data = self.open_data()

                        collection = input('Nft name '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        if len(data['phantom']) != 0:
                            print(Fore.CYAN + 'Private Key' + Fore.RESET)
                            for i in data['phantom']:
                                print(i, data['phantom'][i]['name'])
                        phantom = str(input('Phantom privat key '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        try:
                            phantom = data['phantom'][phantom]['private_key']
                        except:pass
                        
                        price = float(input('Price '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        print(Fore.CYAN + '-RPC-' + Fore.RESET)
                        rpc_id = []
                        i = 0
                        
                        for id in data['rpc']:
                            i += 1
                            print(str(i)+ '.', data['rpc'][id]['name'])
                            rpc_id.append(id)
                        
                        id = str(input('> '+Fore.LIGHTMAGENTA_EX)).strip()
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        if id == '':
                            rpc = ['https://ssc-dao.genesysgo.net/', 'https://solana-api.projectserum.com']
                            print(Fore.CYAN + '-Proxy-' + Fore.RESET)
                            file_name = []
                            i = 0
                            
                            for file in glob.glob('proxy/*'):
                                i+=1
                                file_name.append(file)
                                print(str(i)+'.', file.split('proxy/')[-1].split('.txt')[0])
                            
                            if i == 0:
                                input('Proxy list not found. ')
                                return
                            
                            fileName = file_name[int(input('>'+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            proxy = []
                            st = open(fileName, 'r').readlines()
                            for i in range(len(st)):
                                proxy.append(st[i].split('\n')[0])
                        else:
                            rpc = []
                            id = id.split(' ')
                            
                            for i in range(len(id)):
                                rpc.append(data['rpc'][rpc_id[int(id[i])-1]]['rpc'])
                            
                            proxy = [None]
                            fileName = 'proxy/None.txt'
                        
                        delay = float(input('Cooldown '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        threads = int(input('Count tasks '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        self.idTasks += 1
                        self.localTasks[self.idTasks] = {'task_id':str(self.idTasks), 'mode':'MESniper', 'product':collection, 'proxy':fileName.split('proxy/')[-1].split('.txt')[0], 'time':'0', 'cooldown':str(delay), 'status':'Create', 'logs':[]}
                        self.localTasks[self.idTasks]['logs'].append(collection+'/'+str(price)+'/'+ fileName.split('proxy/')[-1].split('.txt')[0]+'/'+str(delay)+'/'+str(threads))
                        self.localTasks[self.idTasks]['logs'].append(rpc)
                        threading.Thread(target=Sniper, args=(collection, price, delay, threads, phantom, rpc, proxy, fileName.split('proxy/')[-1].split('.txt')[0], self.idTasks, data['dshook'])).start()

                        time.sleep(1)
                        input(Fore.GREEN + 'SUCCESS' + Fore.RESET)

                        self.presence('Sniping ME')

                    elif select == '6':
                        data = self.open_data()
                        
                        token = input('Token '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        
                        if len(data['phantom']) != 0:
                            print(Fore.CYAN + 'Private Key' + Fore.RESET)
                            for i in data['phantom']:
                                print(i, data['phantom'][i]['name'])
                        
                        phantom = str(input('Phantom privat key '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        try:
                            phantom = data['phantom'][phantom]['private_key']
                        except:pass
                        
                        price = float(input('Price '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        print(Fore.CYAN + '-RPC-' + Fore.RESET)
                        rpc_id = []
                        i = 0
                        for id in data['rpc']:
                            i+= 1
                            print(str(i)+'.', data['rpc'][id]['name'])
                            rpc_id.append(id)
                        
                        id = str(input('> '+Fore.LIGHTMAGENTA_EX)).strip()
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        if id == '':
                            rpc = ['https://ssc-dao.genesysgo.net/', 'https://solana-api.projectserum.com']
                            print(Fore.CYAN + '-Proxy-' + Fore.RESET)
                            
                            file_name = []
                            i = 0
                            for file in glob.glob('proxy/*'):
                                i+=1
                                file_name.append(file)
                                print(str(i)+'.', file.split('proxy/')[-1].split('.txt')[0])
                            
                            if i == 0:
                                input('Proxy list not found. ')
                                
                                return

                            fileName = file_name[int(input('> '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            proxy = []
                            st = open(fileName, 'r').readlines()
                            for i in range(len(st)):
                                proxy.append(st[i].split('\n')[0])
                        else:
                            rpc = []
                            id = id.split(' ')
                            for i in range(len(id)):
                                rpc.append(data['rpc'][rpc_id[int(id[i])-1]]['rpc'])
                            
                            proxy = [None]
                            fileName = 'proxy/None.txt'
                        
                        delay = float(input('Delay '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        
                        self.idTasks += 1
                        self.localTasks[self.idTasks] = {'task_id':str(self.idTasks), 'mode':'FFFSniper', 'product':token, 'proxy':fileName.split('proxy/')[-1].split('.txt')[0], 'time':'0', 'cooldown':str(delay), 'status':'Create', 'logs':[]}
                        threading.Thread(target=FFF_sniper, args=(token, phantom, price, proxy, rpc, delay, data['dshook'], self.idTasks)).start()

                        input(Fore.GREEN + 'SUCCESS' + Fore.RESET)

                    elif select == '7':
                        select = str(input('1. Put reactions\n2. Check Results\n> '))
                        
                        if select == '1':
                            data = self.open_data()
                            
                            for i in range(len(data['token'])):
                                print(Fore.RESET + str(i + 1) + ' ' + data['token'][i])
                            token = input('Numbers Tokens '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            
                            tokens = []
                            if str(token) == "['all']":
                                for i in range(len(data['token'])):
                                    if len(str(data['token'][i])) > 30:
                                        tokens.append(data['token'][i])
                            else:
                                indexs = token.copy()
                                
                                for i in range(len(indexs)):
                                    indexs[i] = int(indexs[i]) - 1

                                for i in range(len(token)):
                                    tokens.append(data['token'][int(token[i]) - 1])

                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            proxy = input('Numbers proxies '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            proxies = []
                            for i in range(len(proxy)):
                                proxies.append(data['proxy'][int(proxy[i]) - 1])
                            delay = input('Delay '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            emoji = input('Emoji ')
                            id_giveaway = input('Id giveaway '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            id_channel = input('Id channel '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            input(self.giveaway(tokens, emoji, id_giveaway, id_channel, proxies))
                            
                        elif select == '2':
                            pass

                    elif select == '8':
                        data = self.open_data()
                        
                        if input('1. Local\n2. Proxy\n> ') == '2':
                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            proxy = int(input('Number proxy '))
                            task_proxy = proxy

                            proxy = {
                                'http': 'http://' + str(self.proxy(data['proxy'][proxy - 1])),
                                'https': 'http://' + str(self.proxy(data['proxy'][proxy - 1]))
                            }
                        else:
                            proxy = None
                            task_proxy = None
                        
                        list = []
                        for i in range(5):
                            b = datetime.today().strftime("%S%f")[:-3]
                            
                            if proxy != None:
                                requests.get('https://mobile.api.prod.veve.me/graphql%27', proxies=proxy)
                            else:
                                requests.get('https://mobile.api.prod.veve.me/graphql%27')
                            
                            a = datetime.today().strftime("%S%f")[:-3]
                            list.append(int(a)-int(b))
                            time.sleep(1)
                        
                        print(list)
                        
                        sr = 0
                        for i in range(len(list)):
                            sr += list[i]
                        print('meduim delay - ' + str(sr/len(list))[:2])

                        timer = input('Drop time ')

                        drop_id = input('Drop id ')

                        if input('1. comics\n2. blindbox\n> ').split() == '1':
                            drop_type = 'comics'
                        else:
                            drop_type = 'blindbox'
                        
                        login = input('Login ')
                        password = input('Password ')
                        
                        name_task = input('Name Task ')
                        
                        if data['api']['AntiCaptcha'] == '' or data['api']['AntiCaptcha'] == ' ' or data['api']['AntiCaptcha'] == None:
                            input(Fore.RED + 'AntiCaptcha key not found' + Fore.RESET)
                            return
                        
                        
                        self.idTasks +=1 
                        self.localTasks[self.idTasks] = {'task_id':str(self.idTasks), 'name':name_task, 'mode':'Veve', 'proxy':str(task_proxy), 'id':str(drop_id), 'time':timer, 'cooldown':'0', 'status':'Create'}
                        
                        threading.Thread(target=Veve, args=(proxy, login, password, drop_id, drop_type, timer, data['api']['AntiCaptcha'], data['dshook'], name_task, self.idTasks)).start()

                        input(Fore.GREEN + 'SUCCESS' + Fore.RESET)

                    elif select == '':
                        self.menu('main')

                elif page == 'data':
                    if select == '1':
                        self.menu('token')
                    elif select == '2':
                        self.menu('proxy')
                    elif select == '3':
                        self.captcha('change', '')
                    elif select == '4':
                        self.dshook('change')
                    elif select == 'api':
                        self.captcha('api', '')
                    elif select == '5':
                        data = self.open_data()
                        
                        a = input('1. Add\n2. Delete\n> '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        
                        if a == '1':
                            data['rpc'][len(data['rpc']) + 1] = {'name': input('Name rpc '), 'rpc': input('Rpc ')}
                        elif a == '2':
                            for i in data['rpc']:
                                print(i, data['rpc'][i]['name'])
                            delete = input('> '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            for i in range(len(delete)):
                                data['rpc'].pop(delete[i])
                        self.save_data(data)
                        
                    elif select == '6':
                        data = self.open_data()
                        
                        a = input('1. Add\n2. Delete\n> '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        if a == '1':
                            data['phantom'][len(data['phantom']) + 1] = {'name': input('Name '), 'private_key': input('PrivateKey ')}
                        elif a == '2':
                            for i in data['phantom']:
                                print(i, data['phantom'][i]['name'])
                            delete = input('> '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                        
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            for i in range(len(delete)):
                                data['phantom'].pop(delete[i])
                        self.save_data(data)
                    elif select == '':
                        self.menu('main')

                elif page == 'token':
                    if select == '1':
                        self.token('add')
                    elif select == '2':
                        self.token('get')
                    elif select == '3':
                        self.token('open')
                    elif select == '4':
                        self.token('del')
                    elif select == '5':
                        func = input('1. HypeSquad\n2. Nickname\n3. Avatar\n> '+Fore.LIGHTMAGENTA_EX)
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        if func in ['1', '3']:
                            data = self.open_data()
                            
                            for i in range(len(data['token'])):
                                print(i + 1, data['token'][i])
                            token = input('Numbers Tokens '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            tokens = []
                            for i in range(len(token)):
                                tokens.append(data['token'][int(token[i]) - 1])
                            
                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            proxy = input('Numbers proxies '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                            proxies = []
                            for i in range(len(proxy)):
                                proxies.append(data['proxy'][int(proxy[i]) - 1])
                            
                            delay = input('Delay '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)
                        if func == '1':
                            input(self.HypeSquad(tokens, proxies, delay))
                        elif func == '2':
                            data = self.open_data()
                            
                            for i in range(len(data['token'])):
                                print(i + 1, data['token'][i])
                            token = data['token'][int(input('Number token '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            for i in range(len(data['proxy'])):
                                print(i + 1, data['proxy'][i])
                            proxy = data['proxy'][int(input('Number proxy '+Fore.LIGHTMAGENTA_EX)) - 1]
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            nickName = input('Nick name '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            password = input('Password '+Fore.LIGHTMAGENTA_EX)
                            print("\n\033[A \033[A"+Style.RESET_ALL)

                            input(self.change_nickname(token, proxy, nickName, password))
                        
                        elif func == '3':
                            link = str(input('Photo link '))
                            if link in [' ', '']:
                                link = ''
                            
                            input(self.change_avatar(tokens, proxies, link, delay))
                    
                    elif select == '6':
                        data = self.open_data()
                        
                        for i in range(len(data['token'])):
                            print(i + 1, data['token'][i])
                        token = input('Numbers Tokens '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        tokens = []
                        for i in range(len(token)):
                            tokens.append(data['token'][int(token[i]) - 1])
                        
                        for i in range(len(data['proxy'])):
                            print(i + 1, data['proxy'][i])
                        proxy = input('Numbers proxies '+Fore.LIGHTMAGENTA_EX).strip().split(' ')
                        print("\n\033[A \033[A"+Style.RESET_ALL)
                        proxies = []
                        for i in range(len(proxy)):
                            proxies.append(data['proxy'][int(proxy[i]) - 1])
                        
                        server_id =  str(input('Id server '+Fore.LIGHTMAGENTA_EX))
                        print("\n\033[A \033[A"+Style.RESET_ALL)

                        input(self.check_count_messages(tokens, proxies, server_id))

                    elif select == '7':
                        data = self.open_data()
                        
                        tokens = []
                        for i in range(len(data['token'])):
                            tokens.append(data['token'][i])
                        proxies = []
                        for i in range(len(data['proxy'])):
                            if len(str(data['proxy'][i])) > 5:
                                proxies.append(data['proxy'][i])
                        
                        input(self.check_token(tokens, proxies))
                    
                    elif select == '':
                        self.menu('data')

                elif page == 'proxy':
                    if select == '1':
                        self.proxy('add')
                    elif select == '2':
                        self.proxy('test')
                    elif select == '3':
                        self.proxy('del')
                    elif select == '4':
                        self.proxy('create_proxylist')
                    elif select == '':
                        self.menu('data')

                elif page == '':
                    pass
                self.menu(page)
            except: 
                logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--CLI-->')
                input(Fore.RED + 'Error. Check logs. Press enter' + Fore.RESET)
                self.menu(page)

    if __name__ == '__main__':
        urllib3.disable_warnings()
        Bot().start()

except:
    logging.exception('[' + datetime.today().strftime("%H:%M:%S:%f")[:-4] + ']' + '<--MAIN-->')