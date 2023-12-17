import pytest
from dotenv import load_dotenv
from redis import StrictRedis

load_dotenv()
import os

from vauth.DB import GroupToken, RegisteredPermissions, UserToken

# Assuming you have a Redis connection
redis_conn = StrictRedis(
    host=os.getenv("REDIS_HOST"), port=os.getenv("REDIS_PORT"), db=os.getenv("REDIS_DB"), decode_responses=True
)


@pytest.fixture(scope="module")
def clear_redis():
    # Clear all data from Redis before running tests
    redis_conn.flushdb()


def test_user_token():
    user_token = UserToken(
        id="1", token="user_token_1", group="group_1", email="user@example.com", permissions=["read", "write"]
    )
    user_token.save(redis_conn)
    retrieved_token = UserToken.get("1")
    assert retrieved_token == user_token


def test_group_token():
    group_token = GroupToken(id="group_1", name="Group 1", permissions=["read"], description="Description for Group 1")
    group_token.save(redis_conn)
    retrieved_group_token = GroupToken.get("group_1")
    assert retrieved_group_token == group_token


def test_registered_permissions():
    registered_permissions = RegisteredPermissions(
        id_index=True, path="/some/path", actions=["read", "write"], description="Description for permission"
    )
    registered_permissions.save(redis_conn)
    retrieved_permissions = RegisteredPermissions.get("/some/path")
    assert retrieved_permissions == registered_permissions
