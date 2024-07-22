# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
from http.client import HTTPException
import json
import os
import sys

from requests import Session
import requests

from app.app_config.config import ConfService


sys.path.append(os.path.dirname(__file__))


from flask import Flask, jsonify, render_template
from flask_session import Session
from flask_cors import CORS
import base64
from binascii import unhexlify
from pycose.messages import Sign1Message
import cbor2
from pycose.keys import EC2Key, CoseKey

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from app_config.config import ConfService as cfgserv


def handle_exception(e):

    return (
        render_template(
            "500.html",
            error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            error_code="Internal Server Error",
        ),
        500,
    )

def page_not_found(e):

    return (
        render_template(
            "500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )


def create_app():

    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = ConfService.secret_key

    #app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    from . import (SCA_routes)

    app.register_blueprint(SCA_routes.sca)

    # config session
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one.
    CORS(app, supports_credentials=True)

    return app