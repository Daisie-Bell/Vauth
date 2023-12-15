# Importing necessary libraries and modules
import hashlib

# Main class for handling user authentication and permissions
import secrets
from typing import List
from uuid import uuid4

from fastapi import Header, HTTPException

from vauth.DB import GroupToken, RegisteredPermissions, UserToken
from vauth.exceptions import InvalidAction, InvalidGroup, InvalidToken, NotRegisterPermission


# Function to login a user
def login(token: str = Header()):
    try:
        return VAuth().login(token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class VAuth:
    """
    VAuth class for handling user authentication and authorization
    """

    def add_user(self, user_group: str, user_permissions: List[str] = []) -> str:
        """
        Method to register a new user

        Args:
        - user_group (str): The name of the user group
        - user_permissions (List[str]): List of permissions to assign to the user (default [])

        Returns:
        - str: The hashed token for the new user
        """
        # Generate a random token
        token = secrets.token_hex(16)  # This will generate a 32 character long hex token

        # Hash the token using SHA512
        hashed_token = hashlib.sha512(token.encode()).hexdigest()

        # Check if the token is valid
        if UserToken.find(UserToken.token == hashed_token).count() != 0:
            raise InvalidToken()

        # Check if the group is valid
        if GroupToken.find(GroupToken.name == user_group).count() != 1:
            raise InvalidGroup()

        if isinstance(hashed_token, bytes):
            hashed_token = hashed_token.decode()

        # If both checks pass, create a new User
        new_user = UserToken(id=uuid4().hex, token=hashed_token, group=user_group, permissions=user_permissions)

        # Save the new user to the database
        new_user.save()
        return hashed_token

    def add_group(self, group_name: str, permissions_group: List[str]):
        """
        Method to add a group

        Args:
        - group_name (str): The name of the group to add
        - permissions_group (List[str]): List of permissions to assign to the group

        Raises:
        - InvalidGroup: If the group already exists
        """
        # Check if the group already exists
        if GroupToken.find(GroupToken.name == group_name).count() > 0:
            raise InvalidGroup("Group already exists")

        # If the group doesn't exist, create a new group
        new_group = GroupToken(id=uuid4().hex, name=group_name, permissions=permissions_group)

        # Save the new group to the database
        new_group.save()

    def add_action_to_permission(self, path_: str, action: str):
        """
        Method to add an action to a registed permission

        Args:
        - path_ (str): The path to register the permission for
        - action (str): The action to register the permission for

        Returns:
        - RegisteredPermissions: The newly created permission
        """
        permission = RegisteredPermissions.find(RegisteredPermissions.path == path_).first()
        permission.actions.append(action)
        permission.save()
        return permission

    def register_permission(self, path_: str, actions_: List[str], indexing: bool, description: str = None):
        """
        Method to register a new permission to the DB

        Args:
        - path_ (str): The path to register the permission for
        - actions_ (List[str]): List of actions to register the permission for
        - indexing (bool): Whether or not to index the permission
        - description (str): Optional description for the permission (default None)

        Returns:
        - RegisteredPermissions: The newly created permission
        """
        permission = RegisteredPermissions(id_index=indexing, path=path_, actions=actions_, description=description)
        permission.save()
        return permission

    def get_user(self, token):
        """
        Method to login a user

        Args:
        - token (str): The token to login with

        Returns:
        - User: The logged in user
        """
        return self.User(token)

    class User:
        """
        Inner User class for handling user-specific data and operations
        """

        token: str
        user: UserToken
        group: GroupToken

        def __init__(self, token, suffix="*") -> None:
            """
            Initialize User with a token and optional suffix

            Args:
            - token (str): The token to initialize the user with
            - suffix (str): Optional suffix for the user (default "*")

            Raises:
            - InvalidToken: If the token is invalid
            """
            if UserToken.find(UserToken.token == token).count() == 1:
                self.token = token
                self.suffix = suffix
                self.user = UserToken.find(UserToken.token == self.token).first()
                self.group = GroupToken.find(GroupToken.name == self.user.group).first()
            else:
                raise InvalidToken()

        def add_permission(self, permission: str):
            """
            Method to add a permission to a user

            Args:
            - permission (str): The permission to add

            Raises:
            - InvalidAction: If the action is invalid
            - NotRegisterPermission: If the permission is not registered
            """
            _ = permission.split(".")
            action = _[1]
            reg = RegisteredPermissions.find(RegisteredPermissions.path == permission).first()

            if reg != [] or reg is not None:
                if action in reg.actions:
                    self.user.permissions.append(permission)
                    self.user.save()
                    return {"message": f"permission added successfully to user {self.user.id}"}
                raise InvalidAction()
            raise NotRegisterPermission()

        def has_permission(self, permission):
            """
            Method to check if a user has a specific permission

            Args:
            - permission (str or List[str]): The permission(s) to check

            Returns:
            - bool: True if the user has the permission(s), False otherwise
            """
            if isinstance(permission, List):
                for _ in permission:
                    if (_ in self.user.permissions) or (_ in self.group.permissions) or ("*" in self.user.permissions):
                        return True
            elif (
                (permission in self.user.permissions)
                or (permission in self.group.permissions)
                or ("*" in self.user.permissions)
            ):
                return True
            return False
