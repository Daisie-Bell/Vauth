# Custom exception classes for handling specific error scenarios

# If the Action is invalid
class InvalidAction(Exception):
    def __init__(self, message="Invalid action"):
        self.message = message
        super().__init__(self.message)


# If the permission is not registered
class NotRegisterPermission(Exception):
    def __init__(self, message="Permission not registered"):
        self.message = message
        super().__init__(self.message)


class InvalidPermission(Exception):
    def __init__(self, message="Invalid permission"):
        self.message = message
        super().__init__(self.message)


# If the token doesn't exist
class InvalidToken(Exception):
    def __init__(self, token=None):
        self.token = token
        self.message = "Invalid token"
        if self.token is not None:
            self.message += f": {self.token}"
        super().__init__(self.message)


# If the group doesn't exist
class InvalidGroup(Exception):
    def __init__(self, group=None):
        self.group = group
        self.message = "Invalid group"
        if self.group is not None:
            self.message += f": {self.group}"
        super().__init__(self.message)
