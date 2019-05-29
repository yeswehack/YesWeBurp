#!/usr/bin/env python
#
# File: api.py
# by @BitK_
#
from .models import ProgramDetails, Program, Hunter, Pages
from javax.swing import JOptionPane


class APIException(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def __str__(self):
        return "[{}] {}".format(self.code, self.message)


class AuthMethod:
    anonymous = "anonymous"
    email_pass = "Email / Password"


class Auth:
    @classmethod
    def get_auth_by_name(cls, name):
        mapping = {
            AuthMethod.anonymous: cls.anonymous,
            AuthMethod.email_pass: cls.email_pass,
        }
        return mapping.get(cls, cls.anonymous)

    @classmethod
    def anonymous(cls):
        def get_token(*args, **kwargs):
            return None

        return get_token

    @classmethod
    def email_pass(cls, email, password):
        def ask_topt(server, fetcher, token):
            code = JOptionPane.showInputDialog(
                None,
                "TOTP Code:",
                "Please enter your TOTP code",
                JOptionPane.PLAIN_MESSAGE,
                None,
                None,
                "",
            )
            data = {"token": token, "code": code.strip()}

            url = "{}/account/totp".format(server)
            response = fetcher.post(url, data).json()
            if "code" in response:
                raise APIException(response["code"], response["message"])

            return response["token"]

        def get_token(server, fetcher):
            data = {"email": email, "password": password}
            url = "{}/login".format(server)
            response = fetcher.post(url, data).json()
            if "totp_token" in response:
                return ask_topt(server, fetcher, response["totp_token"])
            if "code" in response:
                raise APIException(response["code"], response["message"])

            return response["token"]

        return get_token


class YWHApi(object):
    def __init__(self, server, fetcher=None, auth=AuthMethod.anonymous):
        self.useragent = "YWH Python client"
        self.server = server.rstrip("/")
        self.auth = auth

        if fetcher is None:
            try:
                import requests

                self.fetcher = requests
            except ImportError:
                raise ImportError(
                    "Request is not installed\nPlease run:\n  > pip install requests"
                )
        else:
            self.fetcher = fetcher

    @property
    def default_headers(self):
        default_headers = {"User-Agent": self.useragent}
        if self.token is not None:
            default_headers["Authorization"] = "Bearer {}".format(self.token)
        return default_headers

    def handle_error(self, response):
        try:
            message = response.json()["message"]
        except Exception:
            message = "Unknown error"
        raise APIException(response.status_code, message)

    def get(self, path, params={}, headers={}, retry=True):
        url = "{}/{}".format(self.server, path.lstrip("/"))
        headers_with_default = self.default_headers
        headers_with_default.update(headers)

        response = self.fetcher.get(url, params=params, headers=headers_with_default)
        if response.status_code != 200:
            if response.status_code == 401 and retry:
                self.token = None
                return self.get(path, params, headers, False)
            self.handle_error(response)
        return response

    def post(self, path, json={}, headers={}, retry=True):
        url = "{}/{}".format(self.server, path.lstrip("/"))
        headers_with_default = self.default_headers
        headers_with_default.update(headers)

        response = self.fetcher.get(url, json=json, headers=headers_with_default)
        if response.status_code != 200:
            if response.status_code == 401 and retry:
                self.token = None
                return self.post(path, json, headers, False)
            self.handle_error(response)
        return response

    def authenticate(self):
        self.token = self.auth(self.server, self.fetcher)
        return self.token

    def get_programs(self):
        constructor = Pages(Program)
        response = self.get("/programs")
        return constructor(response.json()).items

    def get_program_details(self, slug):
        response = self.get("/programs/{slug}".format(slug=slug))
        return ProgramDetails(response.json())

    def get_user(self):
        try:
            result = Hunter(self.get("/user").json())
        except APIException as e:
            if e.message != "JWT Token not found":
                raise
            result = Hunter({"username": "Anonymous"})
        return result

    def change_server(self, url):
        self.server = url.rstrip("/")
        self.token = None

    def change_auth(self, auth):
        self.auth = auth
        self.token = None
