
from typing import Any, List, Optional

from redis_om import Field, JsonModel

# Define Platform model
class Token_User(JsonModel):
    id: Optional[str] = Field(index=True, primary_key=True)
    token: str = Field(index=True)
    group : str = Field(index=True)
    email : Optional[str] = Field(index=True)
    permissions : List[str]

# Define Platform model
class Tokens_Groups(JsonModel):
    id: Optional[str] = Field(index=True, primary_key=True)
    name : str = Field(index=True)
    permissions: List[str]
    description : Optional[str]

# Define Platform model
class Reg_Perms(JsonModel):
    id_index    : bool
    path        : str = Field(index=True, primary_key=True)
    actions     : List[str]
    description : Optional[str]