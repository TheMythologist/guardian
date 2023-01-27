from typing import Callable

from prompt_toolkit.document import Document
from questionary import ValidationError, Validator

from config.GlobalList import Blacklist, GlobalList, Whitelist


class NameValidator(Validator):
    def __init__(self, global_list: Callable[[], GlobalList]):
        self.list = global_list()

    def validate(self, document: Document):
        name = document.text
        if self.list.has(name):
            raise ValidationError(
                message="Name already in list", cursor_position=len(name)
            )


class NameInBlacklist(NameValidator):
    def __init__(self):
        super().__init__(Blacklist)


class NameInWhitelist(NameValidator):
    def __init__(self):
        super().__init__(Whitelist)
