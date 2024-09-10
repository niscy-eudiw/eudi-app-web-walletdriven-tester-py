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
"""
This SCA_routes.py file is the blueprint of the Wallet service.
"""

import base64
import binascii
import io
import json
import os
from uuid import uuid4
import cbor2
from flask import (
    Blueprint,
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)
import segno
import requests
from requests.auth import HTTPBasicAuth
import cbor2

# from . import oidc_metadata
from pycose.messages import Sign1Message
from pycose.keys import CoseKey
from pycose.headers import Algorithm, KID
from pycose.algorithms import EdDSA
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from pycose.keys.keytype import KtyOKP
from pycose.keys.keyops import SignOp, VerifyOp
import base64
from binascii import unhexlify
from pycose.messages import Sign1Message
import cbor2
from pycose.keys import EC2Key, CoseKey

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509

import secrets
import hashlib

from app_config.config import ConfService as cfgserv

sca = Blueprint("SCA", __name__, url_prefix="/")

sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

code_verifier = None
client_id = "wallet-client"
client_secret = "somesecret2"
redirect_uri = "http://127.0.0.1:5000/oauth/login/code"
service_access_token = None
credentialChosen = None
form_global = None
hash = None

# Change HTML Page
@sca.route('/', methods=['GET', 'POST'])
def base():
    return render_template('auth.html', redirect_url= cfgserv.service_url)

@sca.route('/select_pdf', methods=['GET','POST'])
def select_pdf():
    return render_template('pdf.html', redirect_url= cfgserv.service_url)

@sca.route('/credentials_page', methods=['GET', 'POST'])
def credential_page():
    return render_template('credentials.html', redirect_url= cfgserv.service_url) 
 
@sca.route('/upload_document', methods=['GET','POST'])
def upload_document():

    oid_alg=cfgserv.alg_oid

    form = form_global
    container=form["container"]
    signature_format= form["signature_format"]
    packaging= form["packaging"]
    level= form["level"]
    digest_algorithm= form["algorithm"]
    base64_pdf= hash
    headers ={
        "Content-Type": "application/json",
        'Authorization': "Bearer "+service_access_token["access_token"],
    }

    payload = {
        "credentialID": credentialChosen,
        "documents":[{
            "document":base64_pdf,
            "signature_format":signature_format[0],
            "conformance_level": level,
            "signed_envelope_property":packaging,
            "container": container
        }],
        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
        "request_uri":"http://localhost:8081",
        "clientData": "12345678"
    }

    #return payload
    #return jsonify(payload)
    response = requests.request("POST", cfgserv.SCA + "signatures/signDoc" , headers=headers, data=json.dumps(payload))
    response = response.json()
    # with open(os.path.join("app\pdfs","test.pdf"), "wb") as f:
    #     f.write(base64.b64decode(response["documentWithSignature"][0]))
    return response
    
# starts the authentication process throught the /oauth2/authorize and receives the link to the wallet
@sca.route('/service_authorization', methods=['GET','POST'])
def service_authorization():
    # generate nonce
    global code_verifier
    code_verifier = secrets.token_urlsafe(32)
    print(code_verifier)
    code_challenge_method = "S256"
    print(code_challenge_method)
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).decode()
    print(code_challenge)
    
    # format url-encoded request
    params = {
        "response_type":"code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope":"service",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "lang": "pt-PT",
        "state": "12345678"
    }
    
    uri =  "http://localhost:9000/oauth2/authorize"
    response = requests.get(url = uri, params = params, allow_redirects = False)

    # get location to redirect & cookie returned
    print(response.headers)
    location = response.headers.get("Location")
    print(location)
    cookie = response.headers.get("Set-Cookie")
    print(cookie)

    # show location
    response_json = {"location": location, "cookie": cookie}
    return jsonify(response_json)

# receives the link returned by the wallet after sharing the pid
@sca.route('/service_authorization_link', methods=['GET','POST'])
def continue_authentication():
    
    link = request.get_json().get("link")
    print(link)
    cookie = request.get_json().get("cookie")
    print(cookie)
    
    header = {"Cookie": cookie}
    response = requests.get(url = link, headers = header)
    
    global service_access_token
    service_access_token = response.json()
    
    access_token = response.json()
    print("access token: "+access_token["access_token"])
    return access_token

def authorization_value(username, password):
    value_to_encode = f"{username}:{password}"
    print(value_to_encode)
    encoded_value = base64.b64encode(value_to_encode.encode()).decode('utf-8')
    print(encoded_value)
    return f"Basic {encoded_value}"

@sca.route("/oauth/login/code", methods=["GET", "POST"])
def oauth_login_code():
    print(request)
    
    code = request.args.get("code")
    state = request.args.get("state")
    
    # Print the parameters to the console (or handle them as needed)
    print(f"Code: {code}")
    print(f"State: {state}")
    
    params = {
        "grant_type":"authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier
    }
    
    authorization_basic = authorization_value(client_id, client_secret)
    headers_a = {'Authorization': authorization_basic}
    
    uri =  "http://localhost:9000/oauth2/token"
    response = requests.post(url = uri, params = params, headers = headers_a, allow_redirects = False)
    
    return response.json()

@sca.route("/authorization_credential", methods=["GET", "POST"])
def authorization_credential():
    print("initial token: "+"Bearer "+service_access_token["access_token"])
    
    document= request.files['upload']
    
    form_local= request.form
    global form_global
    form_global = form_local
    
    container=form_local["container"]
    signature_format= form_local["signature_format"]
    packaging= form_local["packaging"]
    level= form_local["level"]
    digest_algorithm= form_local["algorithm"]
    base64_pdf= base64.b64encode(document.read()).decode("utf-8")
    global hash
    hash = base64_pdf
    headers ={
        "Content-Type": "application/json",
        'Authorization': "Bearer "+service_access_token["access_token"],
    }
    payload = {
        "credentialID": credentialChosen,
        "numSignatures": "1",
        "documents":[{
            "document":base64_pdf,
            "signature_format":signature_format[0],
            "conformance_level": level,
            "signed_envelope_property":packaging,
            "container": container
        }],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "authorizationServerUrl":"http://localhost:9000",
        "resourceServerUrl":"http://localhost:8081",
        "clientData": "12345678"
    }
    
    uri = "http://localhost:8082/credential/authorize"
    response = requests.get(url = uri, headers=headers, data=json.dumps(payload), allow_redirects = False)
    print(response.json())
    
    location = response.json().get("location_wallet")
    print(location)
    cookie = response.json().get("session_cookie")
    print(cookie)

    # show location
    response_json = {"location": location, "cookie": cookie}
    
    return render_template('signature_pdf.html', redirect_url=cfgserv.service_url, location=location, cookie=cookie)
    
@sca.route("/credentials_list", methods=["GET", "POST"])
def credentials_list():
    print(service_access_token)
    authorization_header = "Bearer "+service_access_token["access_token"]
    print(authorization_header)
    headers_a = {'Content-Type': 'application/json', 'Authorization': authorization_header}
    
    payload = json.dumps({
        "credentialInfo": "true",
        "certificates": "single",
        "certInfo": "true"
    })

    uri =  "http://localhost:8081/csc/v2/credentials/list"
    response = requests.post(url = uri, data=payload, headers = headers_a, allow_redirects = False)
    return response.json()

@sca.route("/createcredentials", methods=["GET", "POST"])
def createcredentials():
    print(service_access_token)
    authorization_header = "Bearer "+service_access_token["access_token"]
    print(authorization_header)
    headers_a = {'Authorization': authorization_header}
    uri =  "http://localhost:8081/csc/v2/credentials/createCredentials"
    response = requests.get(url = uri, headers = headers_a, allow_redirects = False)
    return response.status_code

@sca.route("/set_credentialId", methods=["GET", "POST"])
def setCredentialId():
    global credentialChosen
    credentialChosen = request.get_json().get("credentialID")
    print(credentialChosen)
    return "success"