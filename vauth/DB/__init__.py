from typing import List, Optional

from redis_om import Field, JsonModel


# Define Platform model
class UserToken(JsonModel):
    """
    A class representing a user token in the database.

    Attributes:
    -----------
    id : Optional[str]
        The user's ID.
    token : str
        The user's token.
    group : str
        The user's group.
    email : Optional[str]
        The user's email.
    permissions : List[str]
        A list of the user's permissions.
    """

    token: str = Field(index=True, primary_key=True)
    group: str = Field(index=True)
    email: Optional[str] = Field(index=True)
    permissions: List[str]


# Define Platform model
class GroupToken(JsonModel):
    """
    A class representing a group token in the database.

    Attributes:
    -----------
    id : Optional[str]
        The group's ID.
    token : str
        The group's token.
    name : str
        The group's name.
    permissions : List[str]
        A list of the group's permissions.
    description : Optional[str]
        An optional description of the group.
    """

    name: str = Field(index=True, primary_key=True)
    permissions: List[str]
    description: Optional[str]


# Define Platform model
class RegisteredPermissions(JsonModel):
    """
    A model representing registered permissions in the database.

    Attributes:
    -----------
    id_index : bool
        A boolean indicating whether the ID should be indexed.
    path : str
        The path representing the permission.
    actions : List[str]er
        A list of actions associated with the permission.
    description : Optional[str]
        An optional description of the permission.
    """

    id_index: bool
    path: str = Field(index=True, primary_key=True)
    actions: List[str]
    description: Optional[str]
