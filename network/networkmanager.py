import requests
from app import version
s = requests.Session()


class Cloud:
    api_url = "https://www.thedigitalarc.com/api/{}"

    def __init__(self, token=None, **kwargs):
        self.token = token

    def _send_request(self, method, endpoint, params=None, payload=None, **kwargs):
        url = self.api_url.format(endpoint)
        headers = {'User-Agent': 'Guardian/{})'.format(version),
                   'Content-Type': 'application/json; charset=UTF-8',
                   'Authorization': self.token if self.token else None}
        for _ in range(3):
            resp = s.request(method=method, url=url, params=params, json=payload, headers=headers, **kwargs)
            if resp.status_code != 502:  # Retry on error 502 "Bad Gateway"
                break

        try:
            resp_text = resp.json(encoding="utf-8")
        except:
            resp_text = resp.text

        return resp.status_code, resp_text

    def get_friends(self):
        code, r = self._send_request('GET', 'guardian/friends')
        return code, r

    def get_pending(self):
        code, r = self._send_request('GET', 'guardian/pending')
        return code, r

    def get_all(self):
        code, r = self._send_request('GET', 'guardian/all')
        return code, r

    def request(self, name):
        param = {
            'name': name
        }
        code, r = self._send_request('POST', 'guardian/request', params=param)
        return code, r

    def revoke(self, name):
        param = {
            'name': name
        }
        code, r = self._send_request('POST', 'guardian/revoke', params=param)
        return code, r

    def accept(self, name):
        param = {
            'name': name
        }
        code, r = self._send_request('POST', 'guardian/accept', params=param)
        return code, r

    def check_token(self):
        code, r = self._send_request('GET', 'authenticate')
        if code == 200:
            return True
        else:
            return False

    def check_connection(self):
        try:
            code, r = self._send_request('GET', 'ping')
            if code == 200:
                return True
            else:
                return False
        except:
            return False

    def version(self):
        code, r = self._send_request('GET', 'software/version/guardian')
        return code, r

    def set_ip(self):
        code, r = self._send_request('POST', 'setclientip', params={'application': 'guardian'})
        return code, r

    def get_ip(self):
        code, r = self._send_request('GET', 'getclientip')
        return code, r
