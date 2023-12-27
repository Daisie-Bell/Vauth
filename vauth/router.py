from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException

from vauth import VAuth, login
from vauth.exceptions import InvalidAction, InvalidGroup, InvalidToken, NotRegisterPermission


# Defining the VAuth class which inherits from APIRouter
class VAuthAPIRouter(APIRouter):
    # Initializing the class with necessary routes and variables
    def __init__(self, *args, **kwargs):
        self.name = "vauth"
        self.global_local = "vauth.*"
        super().__init__(*args, **kwargs)
        print(VAuth().register_permission("vauth", ["read", "create", "update", "delete"], True))
        # Adding routes for different HTTP methods
        self.add_api_route(
            "/register_edit_permission", self.register_permission, methods=["POST"], dependencies=[Depends(login)]
        )
        self.add_api_route("/add_group", self.add_group, methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/register_user", self.register_user, methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/set_permission", self.add_permission, methods=["POST"], dependencies=[Depends(login)])
        self.add_api_route("/test_permission", self.has_permission, methods=["GET"], dependencies=[Depends(login)])

    # API endpoint to register a new permission
    def register_permission(self, permission: Dict, vtoken: str = Depends(login)):
        try:
            if vtoken.has_permission("*"):
                perm = VAuth().register_permission(
                    permission["path"], permission["actions"], permission["indexing"], permission["description"]
                )
                return {"message": "Permission registered successfully", "permission": perm}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to add a group
    def add_group(self, group: str, perms: List[str], vtoken: str = Depends(login)):
        try:
            if vtoken.has_permission("*"):
                VAuth().add_group(group, perms)
                return {"message": "Group added successfully"}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except InvalidGroup as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to register a user
    def register_user(self, group_name: str, perms: List[str], vtoken: str = Depends(login)):
        try:
            if vtoken.has_permission("*"):
                user = VAuth().add_user(group_name, perms)
                return {"message": "User registered successfully", "user": user}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except (InvalidToken, InvalidGroup) as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to add a permission to a user
    def add_user_permission(self, token: str, permission: str, vtoken: str = Depends(login)):
        try:
            if vtoken.has_permission("*"):
                user = VAuth().login(token)
                user.add_permission(permission)
                return {"message": "Permission added successfully"}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except (InvalidToken, InvalidAction, NotRegisterPermission) as e:
            raise HTTPException(status_code=400, detail=str(e))

    # API endpoint to check if a user is allowed a specific permission
    def has_permission(permission: str, vtoken: str = Depends(login)):
        try:
            if vtoken.has_permission(permission):
                return {"has_permission": True}
            else:
                raise HTTPException(status_code=403, detail="Your token isn't allowed to perform this action.")
        except InvalidToken as e:
            raise HTTPException(status_code=400, detail=str(e))
