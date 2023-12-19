from unittest.mock import Mock

import pytest

from vauth import UserToken, VAuth
from vauth.exceptions import InvalidGroup, InvalidToken


@pytest.fixture
def vauth_instance(mocker):
    # Mocking database related functions or classes
    mocker.patch("vauth.UserToken.find", return_value=Mock(count=Mock(return_value=0)))
    mocker.patch("vauth.GroupToken.find", return_value=Mock(count=Mock(return_value=1)))
    return VAuth()


def test_add_user_valid(vauth_instance, mocker):
    # Mocking necessary components for a valid user addition
    mocker.patch("secrets.token_hex", return_value="mocked_token")
    mocker.patch("hashlib.sha512", return_value=Mock(hexdigest=Mock(return_value="hashed_mocked_token")))
    UserToken.save = Mock()

    # Test case for adding a valid user
    result = vauth_instance.add_user(user_group="some_group", user_permissions=["permission1", "permission2"])
    assert result == "hashed_mocked_token"


def test_add_user_invalid_group(vauth_instance):
    # Test case for adding a user with an invalid group
    with pytest.raises(InvalidGroup):
        vauth_instance.add_user(user_group="invalid_group")


def test_add_user_invalid_token(vauth_instance, mocker):
    # Mocking necessary components for an invalid token scenario
    mocker.patch("secrets.token_hex", return_value="mocked_token")
    mocker.patch("hashlib.sha512", return_value=Mock(hexdigest=Mock(return_value="hashed_mocked_token")))
    UserToken.find = Mock(count=Mock(return_value=1))  # Assuming token already exists

    # Test case for adding a user with an invalid token
    with pytest.raises(InvalidToken):
        vauth_instance.add_user(user_group="some_group")


# def test_register_user():
#     vauth = VAuth()
#     token = vauth.register_user("admin", ["read", "create", "update", "delete"])
#     assert token is not None


# def test_add_group():
#     pass

# def test_register_permission():
#     pass

# def test_login():
#     pass

# def test_add_user_permission():
#     pass

# def test_
