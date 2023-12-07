from fastapi import FastAPI, Depends, HTTPException
from vauth import VAuth, login
from vauth import VAuthAPIRouter 



app = FastAPI()

# add router to app
app.include_router(VAuthAPIRouter(),  prefix="/v1/auth")

# Initialize VAuthAPIRouter
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