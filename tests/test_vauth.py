import pytest
from vauth import VAuth


def test_register_user():
    vauth = VAuth()
    token = vauth.register_user("admin", ["read", "create", "update", "delete"])
    assert token is not None


def test_add_group():
    pass

def test_register_permission():
    pass

def test_login():
    pass

def test_add_user_permission():
    pass

def test_