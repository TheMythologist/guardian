import contextlib
import re
import socket

from prompt_toolkit.document import Document
from questionary import ValidationError, Validator

from config.GlobalList import Blacklist, Whitelist

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


class NameInBlacklist(Validator):
    def validate(self, document: Document):
        blacklist = Blacklist()
        name = document.text
        if blacklist.has(name):
            raise ValidationError(
                message="Name already in list", cursor_position=len(name)
            )


class NameInWhitelist(Validator):
    def validate(self, document: Document):
        whitelist = Whitelist()
        name = document.text
        if whitelist.has(name):
            raise ValidationError(
                message="Name already in list", cursor_position=len(name)
            )


class IPInBlacklist(Validator):
    def validate(self, document: Document):
        super().validate(document)
        blacklist = Blacklist()
        ip = document.text
        if ip in blacklist:
            raise ValidationError(message="IP already in list", cursor_position=len(ip))


class IPInWhitelist(IPValidator):
    def validate(self, document: Document):
        super().validate(document)
        whitelist = Whitelist()
        ip = document.text
        if ip in whitelist:
            raise ValidationError(message="IP already in list", cursor_position=len(ip))
