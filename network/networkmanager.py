import requests
from app import version
s = requests.Session()


class Cloud:
    api_url = "https://www.thedigitalarc.com/api/{}"

    def __init__(self, token=None):
        self.token = token

    def _send_request(self, method, endpoint, params=None, payload=None, **kwargs):
        resp, resp_text = None, None
        url = self.api_url.format(endpoint)
        headers = {'User-Agent': 'Guardian/{})'.format(version),
                   'Content-Type': 'application/json; charset=UTF-8',
                   'Authorization': self.token if self.token else None}
        for _ in range(3):
            resp = s.request(method=method, url=url, params=params, json=payload, headers=headers, **kwargs)
            if resp.status_code != 502:  # Retry on error 502 "Bad Gateway"
                break

        if resp.status_code >= 400:
            raise ConnectionError

        try:
            resp_text = resp.json(encoding="utf-8")
        except ValueError:
            resp_text = resp.text

        return resp.status_code, resp_text

    def get_friends(self):
        try:
            code, r = self._send_request('GET', 'guardian/friends')
            return r.get('friends', None)
        except (ConnectionError, AttributeError):
            return None

    def get_allowed(self):
        try:
            code, r = self._send_request('GET', 'guardian/friends')
            return r.get('givenperm', None)
        except (ConnectionError, AttributeError):
            return None

    def get_pending(self):
        try:
            code, r = self._send_request('GET', 'guardian/pending')
            return r.get('pending', None)
        except (ConnectionError, AttributeError):
            return None

    def get_all(self):
        try:
            code, r = self._send_request('GET', 'guardian/all')
            return r.get('friends', None)
        except (ConnectionError, AttributeError):
            return None

    def request(self, name):
        param = {
            'name': name
        }
        try:
            code, r = self._send_request('POST', 'guardian/request', params=param)
            return code == 200, r.get('error', None)
        except (ConnectionError, AttributeError):
            return False, None

    def revoke(self, name):
        param = {
            'name': name
        }
        try:
            code, r = self._send_request('POST', 'guardian/revoke', params=param)
            return code == 200, r.get('error', None)
        except (ConnectionError, AttributeError):
            return False, None

    def accept(self, name):
        param = {
            'name': name
        }
        try:
            code, r = self._send_request('POST', 'guardian/accept', params=param)
            return code == 200, r.get('error', None)
        except (ConnectionError, AttributeError):
            return False, None

    def check_token(self):
        try:
            code, r = self._send_request('GET', 'authenticate')
            return code == 200
        except ConnectionError:
            return False

    def check_connection(self):
        try:
            code, r = self._send_request('GET', 'ping')
            return code == 200
        except ConnectionError:
            return False

    def version(self):
        try:
            code, r = self._send_request('GET', 'software/version/guardian')
            return r
        except ConnectionError:
            return None

    def set_ip(self):
        try:
            code, r = self._send_request('POST', 'setclientip', params={'application': 'guardian'})
            return code == 200
        except ConnectionError:
            return False

    def get_ip(self):
        try:
            code, r = self._send_request('GET', 'getclientip')
            return r
        except ConnectionError:
            return None
