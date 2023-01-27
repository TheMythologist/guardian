import contextlib
import re
import socket

from prompt_toolkit.document import Document
from questionary import ValidationError, Validator

ipv4 = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")


class IPValidator(Validator):
    def validate(self, document: Document) -> None:
        error = ValidationError(
            message="Invalid IP", cursor_position=len(document.text)
        )
        try:
            ip = document.text
            if ipv4.match(ip):
                socket.inet_aton(ip)
        except socket.error:
            raise error

    # TODO: Add an extra validator to check if an IP could be used by R* services (i.e. it's part of Microsoft Azure)

    @staticmethod
    def validate_get(text: str) -> str:
        error = ValidationError(message="Invalid IP", cursor_position=len(text))
        with contextlib.suppress(socket.error):
            if ipv4.match(text):
                socket.inet_aton(text)
                return text
        raise error
