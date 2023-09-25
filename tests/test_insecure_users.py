from datasette.app import Datasette
import pytest
from datasette_insecure_users import hash_password, verify_password
from datasette_insecure_users import hash_password, verify_password


@pytest.mark.asyncio
async def test_plugin_is_installed():
    datasette = Datasette(memory=True)
    response = await datasette.client.get("/-/plugins.json")
    assert response.status_code == 200
    installed_plugins = {p["name"] for p in response.json()}
    assert "datasette-insecure-users" in installed_plugins


def test_hash():
    assert (
        hash_password("alex", b"a")
        == b"\xfc\x17I8\xf1\xd7W&\xf7\xaa\xee\x93k\xba\x99\xb32\x07\xa3\xd6 \x87\x8fv\x90\xab\x07\x1c\xb6@\xbe\xfb"
    )
    assert not verify_password("alex", b"a", b"nonsense")


@pytest.mark.asyncio
async def test_api():
    datasette = Datasette(memory=True)

    # test traditional login, alex/hunter2
    response = await datasette.client.post(
        "/-/datasette-insecure-users/login",
        data={"username": "alex", "password": "hunter2"},
    )
    assert response.status_code == 302
    actor_cookie = response.cookies["ds_actor"]
    assert datasette.unsign(actor_cookie, "actor")["a"]["id"] == "alex"

    users = (
        await datasette.get_internal_database().execute(
            "select * from datasette_insecure_users_users"
        )
    ).rows
    assert len(users) == 1
    assert users[0]["id"] == 1
    assert users[0]["username"] == "alex"
    assert type(users[0]["password_salt"]) == bytes
    assert type(users[0]["password_hash"]) == bytes

    # wrong password on traditional login should 403
    response = await datasette.client.post(
        "/-/datasette-insecure-users/login",
        data={"username": "alex", "password": "wrong-password"},
    )
    assert response.status_code == 403

    # password required on traditional login
    response = await datasette.client.post(
        "/-/datasette-insecure-users/login", data={"username": "alex"}
    )
    assert response.status_code == 403

    # Now try "password optional" method, alex-no-pass
    response = await datasette.client.post(
        "/-/datasette-insecure-users/login", data={"username": "alex-no-pass"}
    )
    assert response.status_code == 302
    actor_cookie = response.cookies["ds_actor"]
    assert datasette.unsign(actor_cookie, "actor")["a"]["id"] == "alex-no-pass"

    users = (
        await datasette.get_internal_database().execute(
            "select * from datasette_insecure_users_users"
        )
    ).rows
    assert len(users) == 2
    assert users[1]["id"] == 2
    assert users[1]["username"] == "alex-no-pass"
    assert users[1]["password_salt"] is None
    assert users[1]["password_hash"] is None

    # alex-no-pass can login without a password
    response = await datasette.client.post(
        "/-/datasette-insecure-users/login", data={"username": "alex-no-pass"}
    )
    assert response.status_code == 302

    # provided passwords are silently ignored
    response = await datasette.client.post(
        "/-/datasette-insecure-users/login",
        data={"username": "alex-no-pass", "password": "provided"},
    )
    assert response.status_code == 302
