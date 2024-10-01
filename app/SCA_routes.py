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

import base64
import json
import os
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
)
import requests

# from . import oidc_metadata
import base64
import secrets
import hashlib
from app_config.config import ConfService as cfgserv

sca = Blueprint("SCA", __name__, url_prefix="/")

sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

code_verifier = None
service_access_token = None
credential_access_token = None
credentialChosen = None
form_global = None
hash = None
global_file = None
date = None

# Change HTML Page
@sca.route('/', methods=['GET', 'POST'])
def base():
    return render_template('auth.html', redirect_url= cfgserv.service_url)

# starts the authentication process throught the /oauth2/authorize and receives the link to the wallet
@sca.route('/service_authorization', methods=['GET','POST'])
def service_authorization():
    
    # generate nonce
    global code_verifier
    code_verifier = secrets.token_urlsafe(32)
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).decode()
    
    # format url-encoded request
    params = {
        "response_type":"code",
        "client_id": cfgserv.oauth_client_id,
        "redirect_uri": cfgserv.oauth_redirect_uri,
        "scope":"service",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "lang": "pt-PT",
        "state": "12345678"
    }
    uri = cfgserv.AS+"/oauth2/authorize"
    response = requests.get(url = uri, params = params, allow_redirects = False)

    # get location to redirect & cookie returned
    print(response.headers)
    location = response.headers.get("Location")
    print(location)

    # show location
    response_json = {"location": location}
    return jsonify(response_json)

# endpoint where the qtsp will be redirected to after authentication
@sca.route("/oauth/login/code", methods=["GET", "POST"])
def oauth_login_code():
        
    code = request.args.get("code")
    state = request.args.get("state")
    
    # Print the parameters to the console (or handle them as needed)
    print(f"Code: {code}")
    print(f"State: {state}")
    
    params = {
        "grant_type":"authorization_code",
        "code": code,
        "client_id": cfgserv.oauth_client_id,
        "redirect_uri": cfgserv.oauth_redirect_uri,
        "code_verifier": code_verifier
    }
    
    authorization_basic = authorization_value(cfgserv.oauth_client_id, cfgserv.oauth_client_secret)
    headers_a = {'Authorization': authorization_basic}
    
    uri =  cfgserv.AS+"/oauth2/token"
    response = requests.post(url = uri, params = params, headers = headers_a, allow_redirects = False)
    
    print(response.json())
    access_token = response.json()["access_token"]
    
    global service_access_token
    service_access_token = access_token    
    print("access token: "+service_access_token)
    
    return render_template('auth_success.html', redirect_url= cfgserv.service_url, access_token_value=access_token)

@sca.route('/credentials_page', methods=['GET', 'POST'])
def credential_page():
    return render_template('credential.html', redirect_url= cfgserv.service_url) 

@sca.route("/credentials_list", methods=["GET", "POST"])
def credentials_list():
    print(service_access_token)
    authorization_header = "Bearer "+service_access_token
    print(authorization_header)
    headers_a = {'Content-Type': 'application/json', 'Authorization': authorization_header}
    
    payload = json.dumps({
        "credentialInfo": "true",
        "certificates": "single",
        "certInfo": "true"
    })

    uri =  cfgserv.RS+"/csc/v2/credentials/list"
    response = requests.post(url = uri, data=payload, headers = headers_a, allow_redirects = False)
    print(response)
    return response.json()

@sca.route("/set_credentialId", methods=["GET", "POST"])
def setCredentialId():
    global credentialChosen
    credentialChosen = request.get_json().get("credentialID")
    print(credentialChosen)
    return "success"

@sca.route('/select_pdf', methods=['GET','POST'])
def select_pdf():
    return render_template('pdf.html', redirect_url= cfgserv.service_url)

@sca.route("/authorization_credential", methods=["GET", "POST"])
def authorization_credential():
    print("initial token: "+"Bearer "+service_access_token)
    
    document = request.files['upload']
    print(document.filename)
    print(document.content_type)
    
    global global_file
    global_file = document
    
    form_local= request.form
    
    global form_global
    form_global = form_local
    
    container=form_local["container"]
    signature_format= form_local["signature_format"]
    packaging= form_local["packaging"]
    level= form_local["level"]
    digest_algorithm= form_local["algorithm"]
    print(digest_algorithm)
    base64_pdf= base64.b64encode(document.read()).decode("utf-8")
    
    global hash
    hash = base64_pdf
    
    headers = {
        "Content-Type": "application/json",
        'Authorization': "Bearer "+service_access_token,
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
        "hashAlgorithmOID":digest_algorithm,
        "authorizationServerUrl": cfgserv.AS,
        "resourceServerUrl": cfgserv.RS,
        "clientData": "12345678"
    }
    
    uri = cfgserv.SCA+"/credential/authorize"
    response = requests.get(url = uri, headers=headers, data=json.dumps(payload), allow_redirects = False)
    print(response.json())
    
    location = response.json().get("location_wallet")
    print(location)
    cookie = response.json().get("session_cookie")
    print(cookie)
    date_l = response.json().get("signature_date")
    print(date_l)
    
    global date
    date = date_l
    return render_template('credential_authorization.html', redirect_url=cfgserv.service_url, location=location)

@sca.route("/oauth/credential/login/code", methods=["GET", "POST"])
def oauth_credential_login_code():
    
    access_token_form = request.form["access_token"]    
    access_token_form_json = json.loads(access_token_form)    
    access_token = access_token_form_json["access_token"]
    print(access_token)
    
    global credential_access_token
    credential_access_token = access_token
    
    return render_template('credential_authorization_success.html', redirect_url=cfgserv.service_url, access_token_value=credential_access_token)

# Requests to the backend servers
@sca.route('/upload_document', methods=['GET','POST'])
def upload_document():
    form = form_global
    container=form["container"]
    signature_format= form["signature_format"]
    packaging= form["packaging"]
    level= form["level"]
    digest_algorithm= form["algorithm"]
    print(digest_algorithm)
    base64_pdf= hash
    headers ={
        "Content-Type": "application/json",
        'Authorization': "Bearer "+credential_access_token,
    }

    print(date)

    payload = {
        "credentialID": credentialChosen,
        "documents":[{
            "document":base64_pdf,
            "signature_format":signature_format[0],
            "conformance_level": level,
            "signed_envelope_property":packaging,
            "container": container
        }],
        "hashAlgorithmOID": digest_algorithm,
        "request_uri":cfgserv.RS,
        "signature_date": date,
        "clientData": "12345678"
    }
    
    response = requests.request("POST", cfgserv.SCA+"/signatures/signDoc" , headers=headers, data=json.dumps(payload))
    print(response.json()["documentWithSignature"][0])
    print(global_file.filename)
    new_name = add_suffix_to_filename(global_file.filename)
    print(new_name)    
    print(global_file.content_type)  
        
    response_json = {
        "document_string": response.json()["documentWithSignature"][0], 
        "filename": new_name, 
        "content_type": global_file.content_type
    }
    return jsonify(response_json)
    #return response.json()["documentWithSignature"][0]
    
def authorization_value(username, password):
    value_to_encode = f"{username}:{password}"
    print(value_to_encode)
    encoded_value = base64.b64encode(value_to_encode.encode()).decode('utf-8')
    print(encoded_value)
    return f"Basic {encoded_value}"

def add_suffix_to_filename(filename, suffix="_signed"):
    # Split the filename into name and extension
    name, ext = os.path.splitext(filename)
    # Add the suffix before the file extension and return the new name
    return f"{name}{suffix}{ext}"
