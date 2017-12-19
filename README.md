# SQLinator

Uses mitmproxy to intercept all HTTP traffic and automatically forwards HTTP GET & POST requests to SQLMap's API to test for SQLi and XSS


# Installation

**SQLinator only supports Python >= 3.6**

It's recommended to install SQLinator with pipenv: `pipenv install &&  pipenv shell`

# Usage

1. Start the SQLMap API server:
    `python sqlmapapi.py -s`

2. Run this script:
    `mitmdump -s "sqlinator.py <target domain>"`

3. Start clicking through the target website

4. Profit
