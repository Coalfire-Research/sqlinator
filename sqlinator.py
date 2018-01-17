#! /usr/bin/env python3.6


# 1. Start the SQLMap API server:
#    python sqlmapapi.py -s
#
# 2. Run this script:
#    mitmdump -s "sqlinator.py <target domain>"
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
import sys
from requests.exceptions import ConnectionError
#from mitmproxy.script import concurrent
from mitmproxy import ctx
from time import sleep

seen_urls = set()
found_vulns = set()


class Sqlinator:

    def __init__(self, args):
        self.args = args
        self.level = args.level
        self.risk = args.risk
        self.api_server = args.api_server
        self.domain = re.compile(rf'{args.domain}')

    def create_task(self):
        r = requests.get(f'{self.api_server}/task/new').json()
        assert r['success'] is True
        return r['taskid']

    def start_scan(self, taskid, data):
        r = requests.post(f'{self.api_server}/scan/{taskid}/start', json=data).json()
        assert r['success'] is True

    # Adding the concurrent decorator throws a "TypeError: request() missing 1 required positional argument: 'flow'" error
    # Not sure what that's all about, removing it for now
    #@concurrent
    def response(self, flow):
        if not re.findall(self.domain, flow.request.host) or flow.response.status_code != 200:
            return flow

        try:
            content_type = flow.response.headers['Content-Type']
            if content_type.lower().find('image') != -1:
                return flow
        except KeyError:
            pass

        data = {
            'url': flow.request.url,
            'randomAgent': True,
            'level': self.level,
            'risk': self.risk
        }

        try:
            data['cookie'] = flow.request.headers['Cookie']
        except KeyError:
            pass

        if flow.request.method == 'GET' and ('GET', flow.request.url) not in seen_urls:
            taskid = self.create_task()

            self.start_scan(taskid, data)

            seen_urls.add(('GET', flow.request.url))

            ctx.log.info(f'[+] Submitted HTTP GET request with taskID {taskid} to sqlmap')

        elif flow.request.method == 'POST' and ('POST', flow.request.url) not in seen_urls:
            taskid = self.create_task()

            data['method'] = 'POST'
            if len(flow.request.content):
                data['data'] = flow.request.text

            self.start_scan(taskid, data)

            seen_urls.add(('POST', flow.request.url))

            ctx.log.info(f'[+] Submitted HTTP POST request with taskID {taskid} to sqlmap')

        else:
            ctx.log.info(f'[*] Ignoring HTTP {flow.request.method} request')


def log_watcher(api_server):
    while True:
        tasks = requests.get(f'{api_server}/admin/0/list').json()
        assert tasks['success'] is True

        for taskid, status in tasks['tasks'].items():
            if status == 'terminated':
                data = requests.get(f'{api_server}/scan/{taskid}/data').json()
                logs = requests.get(f'{api_server}/scan/{taskid}/log').json()
                assert data['success'] is True
                assert logs['success'] is True

                r = requests.post(f'{api_server}/option/{taskid}/get', json={'option': 'url'}).json()
                assert r['success'] is True

                url = r['url']

                if len(data['data']):
                    if ('SQLi', url) not in found_vulns:
                        ctx.log.info(f'[!] {url} -> Found SQL Injection in url ')
                        found_vulns.add(('SQLi', url))

                for entry in logs['log']:
                    message = entry['message']
                    if message.find('(XSS)') != -1 and ('XSS', url) not in found_vulns:
                        ctx.log.info(f"[!] {url} -> {message}")
                        found_vulns.add(('XSS', url))

        sleep(5)


def signal_handler(signal, frame):
    if found_vulns:
        ctx.log.info('[*] Outputting results to results.txt')
        with open('results.txt', 'a+') as results:
            for vuln in found_vulns:
                vtype, url = vuln
                results.write(f'{vtype} {url}\n')

    sys.exit(0)


def start():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('domain', type=str, help='Domain in scope (supports regex)')
    parser.add_argument('-l', '--level', dest='level', default=1, choices={1, 2, 3, 4, 5}, type=int, help='Level of tests to perform (1-5, default: 1)')
    parser.add_argument('-r', '--risk', dest='risk', default=1, choices={1, 2, 3}, type=int, help='Risk of tests to perform (1-3, default: 1)')
    parser.add_argument('-a', '--api-server', dest='api_server', default='http://127.0.0.1:8775', type=str, help="SQLMap API server URL (default: http://127.0.0.1:8775)")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    ctx.log.info("[*] Connecting to SQLMap's API ")
    while True:
        try:
            tasks = requests.get(f'{args.api_server}/admin/0/list').json()
            assert tasks['success'] is True
            ctx.log.info('[+] Connected')
            break
        except ConnectionError:
            sleep(5)

    t = threading.Thread(target=log_watcher, args=(args.api_server,), daemon=True)
    t.start()

    return Sqlinator(args)
