import os
import pytest

os.environ.setdefault("FLASK_SECRET", "test-secret")
from app import create_app


@pytest.fixture
def app():
    return create_app(":memory:")


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username="alice", password="alice-pw"):
    return client.post("/login", data={"username": username, "password": password})
