import re
import socket

from prompt_toolkit.document import Document
from questionary import ValidationError, Validator

ipv4 = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")
domain = re.compile(
    r"^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[\[a-z0-9]+)?)+)*$"
)


class IPValidator(Validator):
    def validate(self, document: Document):
        error = ValidationError(
            message="Not a valid IP or URL", cursor_position=len(document.text)
        )
        try:
            ip = document.text
            if ipv4.match(ip):
                socket.inet_aton(ip)
            elif not domain.match(ip):
                raise error
        except socket.error:
            raise error

    # TODO: Add an extra validator to check if an IP could be used by R* services (i.e. it's part of Microsoft Azure)

    @staticmethod
    def validate_get(text: str):
        error = ValidationError(
            message="Not a valid IP or URL", cursor_position=len(text)
        )
        try:
            ip = text
            if ipv4.match(ip):
                socket.inet_aton(ip)
            elif domain.match(ip):
                try:
                    ip = socket.gethostbyname(text)
                except socket.gaierror:
                    raise ValidationError(
                        message=f"URL {text} can't be resolved to IP",
                        cursor_position=len(text),
                    )
                socket.inet_aton(ip)
            else:
                raise error
            return ip
        except socket.error:
            raise error
