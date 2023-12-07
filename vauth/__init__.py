# Importing necessary libraries and modules
import hashlib
import secrets
from typing import List
from uuid import uuid4
from vauth.DB import Token_User, Tokens_Groups, Reg_Perms
from vauth.exceptions import InvalidAction, InvalidGroup, InvalidToken, NotRegisterPermission
from fastapi import APIRouter, HTTPException, Depends, Header
from typing import Dict
from redis_om import Migrator

# Main class for handling user authentication and permissions
import secrets
import hashlib
from typing import List
from uuid import uuid4

class VAuth:
    """
    VAuth class for handling user authentication and authorization
    """

    def register_user(self, user_group: str, perms: List[str] = []) -> str:
        """
        Method to register a new user

        Args:
        - user_group (str): The name of the user group
        - perms (List[str]): List of permissions to assign to the user (default [])

        Returns:
        - str: The hashed token for the new user
        """
        # Generate a random token
        token = secrets.token_hex(16)  # This will generate a 32 characters long token

        # Hash the token using SHA512
        hashed_token = hashlib.sha512(token.encode()).hexdigest()

        # Check if the token is valid
        if Token_User.find(Token_User.token == hashed_token).count() != 0:
            raise InvalidToken()

        # Check if the group is valid
        if Tokens_Groups.find(Tokens_Groups.name == user_group).count() != 1:
            raise InvalidGroup()

        if isinstance(hashed_token, bytes):
            hashed_token = hashed_token.decode()

        # If both checks pass, create a new User
        new_user = Token_User(
            id = uuid4().hex,
            token=hashed_token,
            group=user_group,
            permissions=perms
        )

        # Save the new user to the database
        new_user.save()
        return hashed_token

    def add_group(self, group_name: str,permissions_group : List[str]):
        """
        Method to add a group

        Args:
        - group_name (str): The name of the group to add
        - permissions_group (List[str]): List of permissions to assign to the group

        Raises:
        - InvalidGroup: If the group already exists
        """
        # Check if the group already exists
        if Tokens_Groups.find(Tokens_Groups.name == group_name).count() > 0:
            raise InvalidGroup("Group already exists")

        # If the group doesn't exist, create a new group
        new_group = Tokens_Groups(id = uuid4().hex,name=group_name,permissions=permissions_group)

        # Save the new group to the database
        new_group.save()

    def add_permission_rg(self,path_ : str,action : str):
        """
        Method to register a new permission

        Args:
        - path_ (str): The path to register the permission for
        - action (str): The action to register the permission for

        Returns:
        - Reg_Perms: The newly created permission
        """
        perm = Reg_Perms.find(Reg_Perms.path == path_).first()
        perm.actions.append(action)
        perm.save()
        return perm

    def register(self,path_ : str,actions_ : List[str],indexing : bool,description : str = None):
        """
        Method to register a new permission

        Args:
        - path_ (str): The path to register the permission for
        - actions_ (List[str]): List of actions to register the permission for
        - indexing (bool): Whether or not to index the permission
        - description (str): Optional description for the permission (default None)

        Returns:
        - Reg_Perms: The newly created permission
        """
        perm = Reg_Perms(
                    id_index = indexing,
                    path=path_,
                    actions=actions_,
                    description=description
                )
        perm.save()
        return perm

    def login(self,token):
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
        token : str
        user  : Token_User
        group : Tokens_Groups

        def __init__(self,token,suffix = "*") -> None:
            """
            Initialize User with a token and optional suffix

            Args:
            - token (str): The token to initialize the user with
            - suffix (str): Optional suffix for the user (default "*")

            Raises:
            - InvalidToken: If the token is invalid
            """
            if Token_User.find(Token_User.token == token).count() == 1:
                self.token  = token
                self.suffix = suffix
                self.start()
            else:
                raise InvalidToken()
            
        def start(self):
            """
            Start method to initialize user and group data
            """
            self.user  = Token_User.find(Token_User.token == self.token).first()
            self.group = Tokens_Groups.find(Tokens_Groups.name == self.user.group).first()

        def add_permission(self,perm : str):
            """
            Method to add a permission to a user

            Args:
            - perm (str): The permission to add

            Raises:
            - InvalidAction: If the action is invalid
            - NotRegisterPermission: If the permission is not registered
            """
            _ = perm.split(".")
            path   = _[0]
            action = _[1]
            reg = Reg_Perms.find(Reg_Perms.path == path).first()
            
            if reg != [] or reg is not None:
                if action in reg.actions:
                    self.user.permissions.append(perm)
                    self.user.save()
                    return {"message":f"permission added successfaly"}
                raise InvalidAction()
            raise NotRegisterPermission()
        
        def is_allow(self,permission):
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
            elif (permission in self.user.permissions) or (permission in self.group.permissions) or ("*" in self.user.permissions):
                return True
            return False

# Running migrations
Migrator().run()
try:
    VAuth().add_group("root",[""])
    VAuth().register_user("root",["*"])
except Exception as e:
    print(e)
    pass

# Function to login a user
def login(token : str = Header()):
    try:
        return VAuth().login(token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Defining the VAuth class which inherits from APIRouter
class VAuthAPIRouter(APIRouter):
    # Initializing the class with necessary routes and variables
    def __init__(self, *args, **kwargs):
        self.name = "vauth"
        self.global_local = "vauth.*"
        super().__init__(*args, **kwargs)
        print(VAuth().register("platform",["read","create","update","delete"],True))
        # Adding routes for different HTTP methods
        self.add_api_route("/register_edit_permission", self.register_permission,  methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/add_group", self.add_group, methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/register_user", self.register_user, methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/set_permission", self.add_permission, methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/test_permission", self.is_allowed, methods=["GET"], dependencies=[Depends(login)])
    
    # API endpoint to register a new permission
    def register_permission(permission: Dict, vtoken: str = Depends(login)):
        try:
            if vtoken.is_allow("*"):
                perm = VAuth().register(permission['path'], permission['actions'], permission['indexing'], permission['description'])
                return {"message": "Permission registered successfully", "permission": perm}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    # API endpoint to add a group
    def add_group(group: str, perms: List[str], vtoken: str = Depends(login)):
        try:
            if vtoken.is_allow("*"):
                VAuth().add_group(group, perms)
                return {"message": "Group added successfully"}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except InvalidGroup as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to register a user
    def register_user(group_name: str, perms: List[str], vtoken: str = Depends(login)):
        try:
            if vtoken.is_allow("*"):
                user = VAuth().register_user(group_name, perms)
                return {"message": "User registered successfully","user":user}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except (InvalidToken, InvalidGroup) as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to add a permission to a user
    def add_permission(token: str, permission: str, vtoken: str = Depends(login)):
        try:
            if vtoken.is_allow("*"):
                user = VAuth().login(token)
                user.add_permission(permission)
                return {"message": "Permission added successfully"}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except (InvalidToken, InvalidAction, NotRegisterPermission) as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to check if a user is allowed a specific permission
    def is_allowed(permission: str, vtoken: str = Depends(login)):
        try:
            if vtoken.is_allow(permission):
                return {"is_allowed": True}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except InvalidToken as e:
            raise HTTPException(status_code=400, detail=str(e))