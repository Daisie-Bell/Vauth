## VAuth - User Authentication and Permission Management System

VAuth is a Python implementation of a user authentication and permission management system using FastAPI and Redis. It includes classes and methods for registering users, groups, and permissions, as well as checking if a user has permission to perform a certain action.

### Installation

To install VAuth, you can use poetry:

```bash
poetry add git+https://github.com/Vortex5Root/Redis_Auth.git
```

### Usage

To use VAuth, you need to create an instance of the `VAuth` class:

```python
from vauth import VAuth

vauth = VAuth()
```

#### Registering a New User

To register a new user, you can use the `register_user` method:

```python
token = vauth.register_user("admin", ["read", "create", "update", "delete"])
```

This will create a new user with the specified group and permissions, and return a hashed token for the user.

#### Adding a Group

To add a new group, you can use the `add_group` method:

```python
vauth.add_group("admin", ["read", "create", "update", "delete"])
```

This will create a new group with the specified name and permissions.

#### Registering a New Permission

To register a new permission, you can use the `register` method:

```python
vauth.register("admin.read", ["read"], True, "Allows users to read admin data")
```

This will register a new permission for the specified path and actions, and index it for faster lookup.

#### Logging In

To log in a user, you can use the `login` method:

```python
user = vauth.login(token)
```

This will return a `User` object for the specified token.

#### Adding a Permission to a User

To add a permission to a user, you can use the `add_permission` method:

```python
user.add_permission("admin.read")
```

This will add the specified permission to the user.

#### Checking if a User Has Permission

To check if a user has permission to perform a certain action, you can use the `is_allow` method:

```python
user.is_allow("admin.read")
```

This will return `True` if the user has permission to perform the specified action, and `False` otherwise.

### Example

Here is an example of how to use VAuth to protect a route:

```python
from fastapi import FastAPI, Depends, HTTPException
from vauth import VAuth, login
from vauth import Vauth

app = FastAPI()

# add router to app
app.include_router(Vauth(),  prefix="/v1/auth")

# Initialize VAuth
vauth = VAuth()

try:
    # Register a new permission
    vauth.register("admin", ["read", "create", "update", "delete"], True)
except Exception as e:
    print(e)
try:
    # Register a new role
    vauth.add_group("admin", ["admin.read", "admin.create", "admin.update", "admin.delete"])
except Exception as e:
    print(e)
try:
    # Register a new user
    token = vauth.register_user("admin", ["*"])
except Exception as e:
    print(e)
# Define a route that requires authentication
@app.get("/protected")
def protected_route(token: str = Depends(login)):
    # Check if the token has permission to access this route
    if not token.is_allow("admin.read"):
        raise HTTPException(status_code=403, detail="You don't have permission to access this route.")
    return {"message": "You have successfully accessed the protected route."}
```

In this example, we register a new role with full permissions, register a new user with the `admin` group and all permissions, and define a route that requires authentication. We then use the `login` dependency to authenticate the user, and check if the user has permission to access the route using the `is_allow` method. If the user has permission, we return a success message, otherwise we raise an HTTPException with a 403 status code.