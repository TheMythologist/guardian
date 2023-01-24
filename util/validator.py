import re
import socket

from prompt_toolkit.document import Document
from questionary import ValidationError, Validator

from network import networkmanager
from util.data import CustomList

ipv4 = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")
domain = re.compile(
    r"^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[\[a-z0-9]+)?)+)*$"
)
blacklist = CustomList("blacklist")
custom_ips = CustomList("custom_ips")


class NameInCustom(Validator):
    def validate(self, document: Document):
        global custom_ips
        if custom_ips.has(document.text):
            raise ValidationError(
                message="Name already in list", cursor_position=len(document.text)
            )


class NameInBlacklist(Validator):
    def validate(self, document: Document):
        global blacklist
        if blacklist.has(document.text):
            raise ValidationError(
                message="Name already in list", cursor_position=len(document.text)
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


class IPInCustom(IPValidator):
    def validate(self, document: Document):
        super().validate(document)
        global custom_ips
        if document.text in custom_ips or custom_ips.has(document.text, "value"):
            raise ValidationError(
                message="IP already in list", cursor_position=len(document.text)
            )


class IPInBlacklist(Validator):
    def validate(self, document: Document):
        super().validate(document)
        global blacklist
        if document.text in blacklist or blacklist.has(document.text, "value"):
            raise ValidationError(
                message="IP already in list", cursor_position=len(document.text)
            )


class ValidateToken(Validator):
    def validate(self, document: Document):
        conn = networkmanager.Cloud(document.text)
        if not conn.check_connection():
            raise ValidationError(
                message="DigitalArc is unavailable, unable to check token",
                cursor_position=len(document.text),
            )

        if not conn.check_token():
            raise ValidationError(
                message="Token invalid", cursor_position=len(document.text)
            )
