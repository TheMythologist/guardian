from questionary import ValidationError, Validator
import ipaddress
import socket
import re
from network import networkmanager

ipv4 = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")
domain = re.compile(
    r"^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[\[a-z0-9]+)?)+)*$"
)


class NameInCustom(Validator):
    def validate(self, document):
        global custom_ips
        if custom_ips.has(document.text):
            # Move cursor to end
            raise ValidationError(
                message="Name already in list", cursor_position=len(document.text)
            )


class NameInBlacklist(Validator):
    def validate(self, document):
        global blacklist
        if blacklist.has(document.text):
            # Move cursor to end
            raise ValidationError(
                message="Name already in list", cursor_position=len(document.text)
            )


class IPValidator(Validator):
    def validate(self, document):
        # Move cursor to end
        error = ValidationError(
            message="Not a valid IP or URL", cursor_position=len(document.text)
        )
        try:
            ip = document.text
            if ipv4.match(ip):
                ipaddress.IPv4Address(ip)
            elif not domain.match(ip):
                raise error
        except (ipaddress.AddressValueError, socket.gaierror):
            raise error

    # TODO: Add an extra validator to check if an IP could be used by R* services (i.e. it's part of Microsoft Azure)

    @staticmethod
    def validate_get(text):
        # Move cursor to end
        error = ValidationError(
            message="Not a valid IP or URL", cursor_position=len(text)
        )
        try:
            ip = text
            if ipv4.match(ip):
                ipaddress.IPv4Address(ip)
            elif domain.match(ip):
                ip = socket.gethostbyname(text)
                ipaddress.IPv4Address(ip)
            else:
                raise error
            return ip
        except ipaddress.AddressValueError:
            raise error
        except socket.gaierror:
            # Move cursor to end
            raise ValidationError(
                message=f"URL {text} can't be resolved to IP",
                cursor_position=len(text),
            )


class IPInCustom(IPValidator):
    def validate(self, document):
        super().validate(document)
        global custom_ips
        if document.text in custom_ips or custom_ips.has(document.text, "value"):
            # Move cursor to end
            raise ValidationError(
                message="IP already in list", cursor_position=len(document.text)
            )


class IPInBlacklist(Validator):
    def validate(self, document):
        super().validate(document)
        global blacklist
        if document.text in blacklist or blacklist.has(document.text, "value"):
            # Move cursor to end
            raise ValidationError(
                message="IP already in list", cursor_position=len(document.text)
            )


class ValidateToken(Validator):
    def validate(self, document):
        conn = networkmanager.Cloud(document.text)
        if not conn.check_connection():
            # Move cursor to end
            raise ValidationError(
                message="DigitalArc is unavailable, unable to check token",
                cursor_position=len(document.text),
            )

        if not conn.check_token():
            # Move cursor to end
            raise ValidationError(
                message="Token invalid", cursor_position=len(document.text)
            )
