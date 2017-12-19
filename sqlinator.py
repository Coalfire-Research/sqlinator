#! /usr/bin/env python3.6


# 1. Start the SQLMap API server:
#    python sqlmapapi.py -s
#
# 2. Run this script:
#    mitmdump -s sqlinator.py
#
# 3. Start clicking through the target website
#
# 4. Profit


# Made with <3 by @byt3bl33d3r

import requests
import threading
import signal
import re
import argparse
from requests.exceptions import ConnectionError
#from mitmproxy.script import concurrent
from time import sleep
from sys import exit


API_SERVER = "http://127.0.0.1:8775"

level = 1  # (1-5)
risk = 1   # (1-3)

seen_urls = set()
found_vulns = set()


class Sqlinator:

    def __init__(self, args):
        self.args = args
        self.domain = re.compile(args.domain)

    def create_task(self):
        r = requests.get(f'{API_SERVER}/task/new').json()
        assert r['success'] is True
        return r['taskid']

    def start_scan(self, taskid, data):
        r = requests.post(f'{API_SERVER}/scan/{taskid}/start', json=data).json()
        assert r['success'] is True

    #Adding the concurrent decorator throws a "TypeError: request() missing 1 required positional argument: 'flow'" error
    #Not sure what that's all about, removing it for now
    #@concurrent
    def request(self, flow):
        if not re.findall(self.domain, flow.request.host):
            return flow

        data = {
            'url': flow.request.url,
            'randomAgent': True,
            'level': level,
            'risk': risk
        }

        try:
            data['cookie'] = flow.request.headers['Cookie']
        except KeyError:
            pass

        if flow.request.method == 'GET' and ('GET', flow.request.url) not in seen_urls:
            taskid = self.create_task()

            self.start_scan(taskid, data)

            seen_urls.add(('GET', flow.request.url))

            print(f'[+] Submitted HTTP GET request with taskID {taskid} to sqlmap')

        elif flow.request.method == 'POST' and ('POST', flow.request.url) not in seen_urls:
            taskid = self.create_task()

            data['method'] = 'POST'
            if len(flow.request.content):
                data['data'] = flow.request.text

            self.start_scan(taskid, data)

            seen_urls.add(('POST', flow.request.url))

            print(f'[+] Submitted HTTP POST request with taskID {taskid} to sqlmap')

        else:
            print(f'[*] Ignoring HTTP {flow.request.method} request')


def log_watcher():
    while True:
        tasks = requests.get(f'{API_SERVER}/admin/0/list').json()
        assert tasks['success'] is True

        for taskid, status in tasks['tasks'].items():
            if status == 'terminated':
                data = requests.get(f'{API_SERVER}/scan/{taskid}/data').json()
                logs = requests.get(f'{API_SERVER}/scan/{taskid}/log').json()
                assert data['success'] is True
                assert logs['success'] is True

                r = requests.post(f'{API_SERVER}/option/{taskid}/get', json={'option': 'url'}).json()
                assert r['success'] is True

                url = r['url']

                if len(data['data']):
                    if ('SQLi', url) not in found_vulns:
                        print(f'[!] {url} -> Found SQL Injection in url ')
                        found_vulns.add(('SQLi', url))

                for entry in logs['log']:
                    message = entry['message']
                    if message.find('(XSS)') != -1:
                        if ('XSS', url) not in found_vulns:
                            print(f"[!] {url} -> {message}")
                            found_vulns.add(('XSS', url))

        sleep(5)


def signal_handler(signal, frame):
    print('[*] Outputting results to results.txt')
    with open('results.txt', 'a+') as results:
        for vuln in found_vulns:
            vtype, url = vuln
            results.write(f'{vtype} {url}\n')

    exit(0)


def start():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('domain', type=str)
    args = parser.parse_args()

    print("[*] Connecting to SQLMap's API ")
    while True:
        try:
            tasks = requests.get(f'{API_SERVER}/admin/0/list').json()
            assert tasks['success'] is True
            print('[+] Connected')
            break
        except ConnectionError:
            sleep(5)

    t = threading.Thread(target=log_watcher, daemon=True)
    t.start()

    return Sqlinator(args)
