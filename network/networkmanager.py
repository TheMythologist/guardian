import contextlib
from typing import Any, Literal, Optional

import requests

from app import version

s = requests.Session()


class Cloud:
    api_url = "https://www.thedigitalarc.com/api/"

    def __init__(self, token: Optional[str] = None):
        self.token = token

    def __send_request(
        self,
        method: Literal["GET", "POST"],
        endpoint: str,
        params: Optional[dict[str, str]] = None,
        payload=None,
        **kwargs,
    ) -> tuple[int, dict | str]:
        url = self.api_url + endpoint
        headers = {
            "User-Agent": f"Guardian/{version})",
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": self.token or None,
        }
        for _ in range(3):
            try:
                resp = s.request(
                    method=method,
                    url=url,
                    params=params,
                    json=payload,
                    headers=headers,
                    **kwargs,
                )
                if resp.status_code != 502:
                    break
            except requests.exceptions.RequestException:
                raise ConnectionError

        if resp.status_code >= 400:
            raise ConnectionError

        try:
            resp_text = resp.json()
        except ValueError:
            resp_text = resp.text

        return resp.status_code, resp_text

    def get_friends(self):
        try:
            code, r = self.__send_request("GET", "guardian/friends")
            return r.get("friends", None)
        except (ConnectionError, AttributeError):
            return None

    def get_allowed(self):
        try:
            code, r = self.__send_request("GET", "guardian/friends")
            return r.get("givenperm", None)
        except (ConnectionError, AttributeError):
            return None

    def get_pending(self):
        try:
            code, r = self.__send_request("GET", "guardian/pending")
            return r.get("pending", None)
        except (ConnectionError, AttributeError):
            return None

    def get_all(self):
        try:
            code, r = self.__send_request("GET", "guardian/all")
            return r.get("friends", None)
        except (ConnectionError, AttributeError):
            return None

    def request(self, name: str) -> tuple[bool, Any | None]:
        return self.__send_post_request(name, "guardian/request")

    def revoke(self, name: str) -> tuple[bool, Any | None]:
        return self.__send_post_request(name, "guardian/revoke")

    def accept(self, name: str) -> tuple[bool, Any | None]:
        return self.__send_post_request(name, "guardian/accept")

    def __send_post_request(self, name: str, endpoint: str) -> tuple[bool, Any | None]:
        param = {"name": name}
        with contextlib.suppress(ConnectionError):
            code, r = self.__send_request("POST", endpoint, params=param)
            if isinstance(r, dict):
                return code == 200, r.get("error", None)
        return False, None

    def check_token(self) -> bool:
        return self.__send_check("authenticate")

    def check_connection(self) -> bool:
        return self.__send_check("ping")

    def __send_check(self, endpoint: str) -> bool:
        try:
            code, r = self.__send_request("GET", endpoint)
            return code == 200
        except ConnectionError:
            return False

    def version(self) -> Any | str | None:
        try:
            code, r = self.__send_request("GET", "software/version/guardian")
            return r
        except ConnectionError:
            return None

    def set_ip(self) -> Any | str | None:
        try:
            code, r = self.__send_request(
                "POST", "setclientip", params={"application": "guardian"}
            )
            return code == 200
        except ConnectionError:
            return False

    def get_ip(self) -> Any | str | None:
        try:
            code, r = self.__send_request("GET", "getclientip")
            return r
        except ConnectionError:
            return None
