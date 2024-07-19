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

oidc_metadata = {}

def setup_metadata():
    global oidc_metadata

    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET",cfgserv.metadata_supported_credentials_url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),400
    
    credentials_supported=response.json()["credential_configurations_supported"]
    
    # for credentials_not_sup in cfgserv.credentials_not_supported:
    #     credentials_supported.pop(credentials_not_sup)

    
    # try:
    #     credentials_supported = {}
    #     dir_path = os.path.dirname(os.path.realpath(__file__))

    #     for file in os.listdir(dir_path + "/metadata_config/credentials_supported/"):
    #         if file.endswith("json"):
    #             json_path = os.path.join(
    #                 dir_path + "/metadata_config/credentials_supported/", file
    #             )
    #             with open(json_path, encoding='utf-8') as json_file:
    #                 credential = json.load(json_file)
    #                 credentials_supported.update(credential)

    # except FileNotFoundError as e:
    #     print(f"Metadata Error: file not found. {e}")
    # except json.JSONDecodeError as e:
    #     print(f"Metadata Error: Metadata Unable to decode JSON. {e}")
    # except Exception as e:
    #     print(f"Metadata Error: MetadataAn unexpected error occurred. {e}")

    oidc_metadata["credentials_supported"] = credentials_supported

def setup_trusted_CAs():
    global trusted_CAs
    
    try:
        ec_keys = {}
        dir_path = os.path.dirname(os.path.realpath(__file__))

        for file in os.listdir(dir_path + "/certs/CAs/"):
            if file.endswith("pem"):
                CA_path = os.path.join(
                    dir_path + "/certs/CAs/", file
                    
                )
                with open(CA_path) as der_file:

                    der_data = der_file.read()

                    der_data=der_data.encode()

                    certificate = x509.load_pem_x509_certificate(der_data, default_backend())
                    
                    public_key = certificate.public_key()

                    issuer=certificate.issuer

                    not_valid_before=certificate.not_valid_before_utc

                    not_valid_after=certificate.not_valid_after_utc

                    x = public_key.public_numbers().x.to_bytes(
                        (public_key.public_numbers().x.bit_length() + 7) // 8,  # Number of bytes needed
                        "big",  # Byte order
                    )

                    y = public_key.public_numbers().y.to_bytes(
                        (public_key.public_numbers().y.bit_length() + 7) // 8,  # Number of bytes needed
                        "big",  # Byte order
                    )

                    ec_key = EC2Key(x=x, y=y, crv=1)  # SECP256R1 curve is equivalent to P-256
                    
                    ec_keys.update({issuer:{
                        "certificate":certificate,
                        "public_key":public_key,
                        "not_valid_before":not_valid_before,
                        "not_valid_after":not_valid_after,
                        "ec_key":ec_key
                    }})
                    

    except FileNotFoundError as e:
        print(f"Metadata Error: file not found. {e}")
    except json.JSONDecodeError as e:
        print(f"Metadata Error: Metadata Unable to decode JSON. {e}")
    except Exception as e:
        print(f"Metadata Error: MetadataAn unexpected error occurred. {e}")

    trusted_CAs=ec_keys


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
    # setup_metadata()
    # setup_trusted_CAs()

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