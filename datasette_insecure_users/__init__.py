from datasette import hookimpl, Response
import hashlib
import secrets
from pathlib import Path


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 480000)


def verify_password(
    password_attempt: str, password_salt: bytes, password_hash: bytes
) -> bool:
    compare_hash = hash_password(password_attempt, password_salt)
    return secrets.compare_digest(password_hash, compare_hash)


class Routes:
    async def login(request, datasette):
        db = datasette.get_internal_database()
        if request.actor:
            return Response.redirect("/")
        if request.method == "POST":
            post_vars = await request.post_vars()
            username = post_vars.get("username") or ""
            password = post_vars.get("password") or ""

            results = await db.execute(
                """
                  select
                    username,
                    password_salt,
                    password_hash
                  from datasette_insecure_users_users
                  WHERE username = :username
                """,
                {
                    "username": username,
                },
            )
            row = results.first()
            if not row:
                # user doesn't exist yet, so create it on-the-spot
                if password == "":
                    password_salt = None
                    password_hash = None
                else:
                    password_salt = secrets.token_bytes(16)
                    password_hash = hash_password(password, password_salt)
                await db.execute_write(
                    """
                      INSERT INTO datasette_insecure_users_users(
                        username,
                        password_salt,
                        password_hash
                      )
                      VALUES (:username, :password_salt, :password_hash)
                    """,
                    {
                        "username": username,
                        "password_salt": password_salt,
                        "password_hash": password_hash,
                    },
                )
                response = Response.redirect("/")
                response.set_cookie(
                    "ds_actor", datasette.sign({"a": {"id": username}}, "actor")
                )
                return response

            # username was set up with no password, so login as usual
            if row["password_hash"] is None:
                response = Response.redirect("/")
                response.set_cookie(
                    "ds_actor", datasette.sign({"a": {"id": row["username"]}}, "actor")
                )
                return response
            # otherwise, an existing user with real password, so verify it.
            if verify_password(password, row["password_salt"], row["password_hash"]):
                response = Response.redirect("/")
                response.set_cookie(
                    "ds_actor", datasette.sign({"a": {"id": row["username"]}}, "actor")
                )
                return response
            else:
                return Response.html(
                    await datasette.render_template(
                        "login.html", {"error": "lol pwned"}, request=request
                    ),
                    status=403,
                )

        return Response.html(
            await datasette.render_template("login.html", {}, request=request)
        )


SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


@hookimpl
async def startup(datasette):
    await datasette.get_internal_database().execute_write_script(SCHEMA)


@hookimpl
def register_routes():
    return [
        (r"^/-/datasette-insecure-users/login$", Routes.login),
    ]


@hookimpl
def menu_links(datasette, actor):
    if not actor:
        return [
            {
                "href": datasette.urls.path("/-/datasette-insecure-users/login"),
                "label": "Log in",
            },
        ]
