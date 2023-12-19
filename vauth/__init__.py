# Importing necessary libraries and modules
import hashlib

# Main class for handling user authentication and permissions
import secrets
from typing import List

from fastapi import Header, HTTPException
from redis_om.model.model import NotFoundError

from vauth.DB import GroupToken, RegisteredPermissions, UserToken
from vauth.exceptions import InvalidAction, InvalidGroup, InvalidPermission, InvalidToken, NotRegisterPermission


# Function to login a user
def login(token: str = Header()):
    try:
        return VAuth().get_user(token)
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

        group = None
        try:
            group = GroupToken.get(user_group)
            UserToken.get(hashed_token)
        except Exception as e:
            if isinstance(e, NotFoundError):
                if group is not None:
                    UserToken(token=hashed_token, group=user_group, permissions=user_permissions).save()
                if group is None:
                    raise InvalidGroup()
        return hashed_token

    def add_group(self, group_name: str, permissions: List[str]):
        """
        Method to add a group. If the group already exists, it will update the permissions to the new permissions.

        Args:
        - group_name (str): The name of the group to add
        - permissions (List[str]): List of permissions to assign to the group

        Raises:
        - InvalidGroup: If the group already exists
        """
        try:
            group = GroupToken.get(group_name)
            # Will only update the permissions if they are different
            if group.permissions != permissions:
                group.permissions = permissions
                group.save()
        except Exception as e:
            if isinstance(e, NotFoundError):
                GroupToken(name=group_name, permissions=permissions).save()

    def add_permission(self, path_: str, action: str):
        """
        Method to add an action to a registed permission

        Args:
        - path_ (str): The path to register the permission for
        - action (str): The action to register the permission for

        Returns:
        - RegisteredPermissions: The newly created permission
        """
        try:
            permission = RegisteredPermissions.get(path_)
            if action not in permission.actions:
                permission.actions.append(action)
                permission.save()
            return permission
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise NotRegisterPermission("Permission not registered!")

    def register_permission(self, path_: str, actions_: List[str], indexing: bool, description: str = ""):
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
        permission = RegisteredPermissions(
            path=path_, actions=actions_, id_index=indexing, description=description
        )  # ToDo: why indexing?
        permission.save()
        return permission  # Todo: justify this return

    def get_user(self, token):
        """
        Method to retrive a user from the database

        Args:
        - token (str): The token to login with

        Returns:
        - User: The logged in user
        """
        return self.User(token)

    def get_permission(self, path_: str):
        """
        Method to retrive a permission from the database

        Args:
        - path_ (str): The path to retrive the permission for

        Returns:
        - RegisteredPermissions: The permission
        """
        try:
            return RegisteredPermissions.get(path_)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise NotRegisterPermission("Permission not registered!")

    class User:
        """
        Inner User class for handling user-specific data and operations
        """

        token: str
        user_token: UserToken
        group_token: GroupToken

        def __init__(self, token: str, suffix: str = "*") -> None:
            """
            Initialize User with a token and optional suffix

            Args:
            - token (str): The token to initialize the user with
            - suffix (str): Optional suffix for the user (default "*")

            Raises:
            - InvalidToken: If the token is invalid
            """
            try:
                self.token = token  # Todo : check if token is valid
                self.suffix = suffix
                self.user_token = UserToken.get(token)
                self.group_token = GroupToken.get(self.user_token.group)
            except Exception as e:
                if isinstance(e, NotFoundError):
                    raise InvalidToken()

        def __str__(self) -> str:
            """
            Method to return the string representation of the user

            Returns:
            - str: The string representation of the user
            """
            return f"User Token: {self.user_token}\nGroup Token: {self.group_token}"

        def add_permission(self, permission_path: str):
            """
            Method to add a permission to a user

            Args:
            - permission_path (str): The permission to add, i.e., "group.action"

            Raises:
            - InvalidAction: If the action is invalid
            - NotRegisterPermission: If the permission is not registered
            """

            # validate permission if it's of the form "path.action"
            _ = permission_path.split(".")
            if len(_) != 2:
                raise InvalidPermission()
            else:
                action = _[1]
            try:
                registered_permission = RegisteredPermissions.get(permission_path)
                if action not in registered_permission.actions:
                    raise InvalidAction()
            except Exception as e:
                if isinstance(e, NotFoundError):
                    raise NotRegisterPermission()

        def has_permission(self, permission: str):
            """
            Method to check if a user has a specific permission

            Args:
            - permission (str or List[str]): The permission(s) to check

            Returns:
            - bool: True if the user has the permission(s), False otherwise
            """
            if isinstance(permission, List):
                for _ in permission:
                    if (
                        (_ in self.user_token.permissions)
                        or (_ in self.group_token.permissions)
                        or ("*" in self.user_token.permissions)
                    ):
                        return True
            elif (
                (permission in self.user_token.permissions)
                or (permission in self.group_token.permissions)
                or ("*" in self.user_token.permissions)
            ):
                return True
            return False
