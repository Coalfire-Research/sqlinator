#! /usr/bin/env python3.6

from mitmproxy import ctx
from mitmproxy.script import concurrent
from time import sleep
import requests
import threading

API_SERVER = "http://127.0.0.1:8775"

level = 1  # (1-5)
risk = 1   # (1-3)

seen_urls = set()
found_vulns = set()


class Sqlinator:

    def create_task():
        r = requests.get(f'{API_SERVER}/task/new').json()
        assert r['success'] is True
        return r['taskid']

    @concurrent
    def request(flow):
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
            taskid = Sqlinator.create_task()

            r = requests.post(f'{API_SERVER}/scan/{taskid}/start', json=data).json()
            assert r['success'] is True

            seen_urls.add(('GET', flow.request.url))

            print(f'[+] Submitted HTTP GET request with taskID {taskid} to sqlmap')

        elif flow.request.method == 'POST' and ('POST', flow.request.url) not in seen_urls:

            taskid = Sqlinator.create_task()

            if len(flow.request.content):
                data['method'] = 'POST'
                data['data'] = flow.request.text

            r = requests.post(f'{API_SERVER}/scan/{taskid}/start', json=data).json()
            assert r['success'] is True

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


def start():
    t = threading.Thread(target=log_watcher, daemon=True)
    t.start()

    return Sqlinator()
