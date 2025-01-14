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

import os
import base64
import mimetypes
from flask import (
    Blueprint,
    render_template,
    make_response,
    request,
    jsonify,
    redirect, 
    url_for,
    session
)
import requests
from werkzeug.utils import secure_filename
import base64
import secrets
import hashlib
from app_config.config import ConfService as cfgserv
import qtsp_client, sca_client
from cryptography.x509.oid import _SIG_OIDS_TO_HASH 
from cryptography.hazmat._oid import ObjectIdentifier

sca = Blueprint("SCA", __name__, url_prefix="/")
sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

UPLOAD_FOLDER = 'documents'

env_var = os.getenv('ENV_TYPE', 'demo')

DIGEST_OIDS = {
    "md5": "1.2.840.113549.2.5",
    "sha1": "1.3.14.3.2.26",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha3_224": "2.16.840.1.101.3.4.2.7",
    "sha3_256": "2.16.840.1.101.3.4.2.8",
    "sha3_384": "2.16.840.1.101.3.4.2.9",
    "sha3_512": "2.16.840.1.101.3.4.2.10",
}


@sca.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', redirect_url= cfgserv.service_url)

@sca.route('/tester', methods=['GET', 'POST'])
def main():
    return render_template('main.html', redirect_url= cfgserv.service_url)

@sca.route('/tester/auth', methods=['GET', 'POST'])
def authentication():
    return render_template('auth.html', redirect_url= cfgserv.service_url, env_var=env_var)

# starts the authentication process throught the /oauth2/authorize and receives the link to the wallet
@sca.route('/tester/service_authorization', methods=['GET','POST'])
def service_authorization():
    code_verifier = secrets.token_urlsafe(32)
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()
    
    if(session.get("code_verifier") is not None):
        session.pop("code_verifier")
    session["code_verifier"] = code_verifier
        
    response = qtsp_client.oauth2_authorize_service_request(code_challenge, code_challenge_method)

    # get location to redirect & cookie returned
    if(response.status_code == 400):
        message = response.json()["message"]
        return message, 400
    elif response.status_code == 200:
        return response
    else:
        location = response.headers.get("Location")
        if location.startswith("eudi-openid4vp"):        
            response_json = {"location": location}
            return jsonify(response_json), 302
        else:
            response = requests.get(url=location)
            return response.text, 400

# endpoint where the qtsp will be redirected to after authentication
@sca.route("/tester/oauth/login/code", methods=["GET", "POST"])
def oauth_login_code():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description=request.args.get("error_description")
    
    code_verifier = session["code_verifier"]
    print(f"Code Verifier: {code_verifier}")
    
    if(code == None):
        return error_description, 400
    
    else:
        response = qtsp_client.oauth2_token_request(code, code_verifier) # trades the code for the access token
                
        if(response.status_code == 400):
            error = response.json()["error"]
            error_description = response.json()["error_description"]
            return error_description
        elif(response.status_code == 200):
            response_json = response.json()
            access_token = response_json["access_token"]
            scope = response_json["scope"]
            
            if(scope == "service"):
                if(session.get("code_verifier") is not None):
                    session.pop("code_verifier")
                if(session.get("service_access_token") is not None):
                    session.pop("service_access_token")
                session["service_access_token"] = access_token
                return redirect(url_for("SCA.service_auth_successful"))
            elif(scope == "credential"):
                if(session.get("code_verifier") is not None):
                    session.pop("code_verifier")
                if(session.get("credential_access_token") is not None):
                    session.pop("credential_access_token")
                session["credential_access_token"] = access_token
                return redirect(url_for("SCA.upload_document"))

@sca.route("/tester/service_auth", methods=["GET", "POST"])
def service_auth_successful():
    return render_template('auth_success.html', redirect_url= cfgserv.service_url, access_token_value=session["service_access_token"], env_var=env_var)

@sca.route("/tester/credentials_list", methods=["GET", "POST"])
def credentials_list():
    response = qtsp_client.csc_v2_credentials_list(session["service_access_token"])
    credentials = response.json()
    credentials_ids_list = credentials["credentialIDs"]
    print(credentials_ids_list)
    return render_template('credential.html', redirect_url=cfgserv.service_url, credentials=credentials_ids_list)

@sca.route("/tester/set_credential_id", methods=["GET", "POST"])
def setCredentialId():
    if(session.get("credentialChosen") is not None):
        session.pop("credentialChosen")
    session["credentialChosen"] = request.get_json().get("credentialID")
    
    credential_info = qtsp_client.csc_v2_credentials_info(session["service_access_token"], session["credentialChosen"])
    
    if credential_info.status_code == 200:
        credential_info_json = credential_info.json()
        print(credential_info_json["cert"])
        
        certificate_info = credential_info_json["cert"]
        certificates = certificate_info["certificates"]
        print(certificates)
        
        if(session.get("end_entity_certificate") is not None):
            session.pop("end_entity_certificate")
        session["end_entity_certificate"]=certificates[0]
        
        if(session.get("certificate_chain") is not None):
            session.pop("certificate_chain")
        session["certificate_chain"]=certificates[1]
        
        key_info = credential_info_json["key"]
        key_algos = key_info["algo"]
        
        if(session.get("key_algos") is not None):
            session.pop("key_algos")
        session["key_algos"]=key_algos
        
    return "success"

@sca.route('/tester/select_document', methods=['GET','POST'])
def select_pdf():
    key_algos = session["key_algos"]
    hash_algos = []
    for algo in key_algos:
        hash_algo = _SIG_OIDS_TO_HASH.get(ObjectIdentifier(algo))
        if(hash_algo is not None):
            hash_algos.append({"name":hash_algo.name.upper(), "oid":DIGEST_OIDS.get(hash_algo.name.lower())})
            
    return render_template('pdf.html', redirect_url= cfgserv.service_url, digest_algorithms=hash_algos)

def get_signature_format_simplified(signature_format):
    if signature_format == "PAdES":
        return 'P'
    elif signature_format == "XAdES":
        return 'X'
    elif signature_format == "JAdES":
        return 'J'
    else:
        return 'C'

def get_unique_filename(folder, filename):
    base, ext = os.path.splitext(filename)  # Split the filename into name and extension
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(folder, new_filename)):
        new_filename = f"{base}_{counter}{ext}"
        counter += 1
    return new_filename

def save_document(document):
    filename = secure_filename(document.filename)
    filename = get_unique_filename(UPLOAD_FOLDER, filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    document.save(file_path)
    document.stream.seek(0)
    return file_path

@sca.route("/tester/authorization_credential", methods=["GET", "POST"])
def authorization_credential():
    document = request.files['upload']
    form_local= request.form

    filename = save_document(document)

    session["filename"] = filename # filepath
    session["form_global"] = form_local

    base64_pdf= base64.b64encode(document.read()).decode("utf-8")
    document.stream.seek(0)
    
    container=form_local["container"]
    signature_format= get_signature_format_simplified(form_local["signature_format"])
    signed_envelope_property= form_local["packaging"]
    conformance_level= form_local["level"]
    hash_algorithm_oid= form_local["algorithm"]

    calculate_hash_json = sca_client.calculate_hash_request(
        base64_pdf,
        signature_format,
        conformance_level,
        signed_envelope_property,
        container,
        session["end_entity_certificate"],
        session["certificate_chain"],
        hash_algorithm_oid
    )
    hashes = calculate_hash_json["hashes"]
    if(session.get("hashes") is not None):
        session.pop("hashes")
    session["hashes"] = hashes

    signature_date = calculate_hash_json["signature_date"]
    if(session.get("signature_date") is not None):
        session.pop("signature_date")
    session["signature_date"] = signature_date

    code_verifier = secrets.token_urlsafe(32)    
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()
    
    if(session.get("code_verifier") is not None):
        session.pop("code_verifier")
    session["code_verifier"] = code_verifier
    
    hashes_string = ";".join(hashes)
    print(hashes_string)
    
    response = qtsp_client.oauth2_authorize_credential_request(code_challenge, code_challenge_method, 1, hashes_string, hash_algorithm_oid, session["credentialChosen"])

    if(response.status_code == 302): # redirects to the QTSP OID4VP Authentication Page
        location = response.headers.get("Location")
        print("Location to authenticate: "+ location)
        response_final = make_response(render_template('credential_authorization.html', redirect_url=cfgserv.service_url, location=location, env_var=env_var))
        return response_final
    else:
        message = response.json()["message"]
        return message, 400
    
# Requests to the backend servers
@sca.route('/tester/upload_document', methods=['GET','POST'])
def upload_document():
    form = session["form_global"]
    container=form["container"]
    signature_format= get_signature_format_simplified(form["signature_format"])
    signed_envelope_property= form["packaging"]
    conformance_level= form["level"]
    hash_algorithm_oid= form["algorithm"]
    
    file_path = session["filename"]
    file = open(file_path, "rb")
    print(os.path.basename(file.name))
    document_content = file.read()
    base64_pdf= base64.b64encode(document_content).decode("utf-8")
    
    response = qtsp_client.csc_v2_signatures_signHash(
        session["credential_access_token"],
        session["hashes"],
        hash_algorithm_oid, 
        session["credentialChosen"], 
        "1.2.840.10045.2.1"
    )

    signatures = response.json()["signatures"]
    response = sca_client.obtain_signed_document(
        base64_pdf, 
        signature_format, 
        conformance_level,
        signed_envelope_property, 
        container, 
        session["end_entity_certificate"],
        session["certificate_chain"],
        hash_algorithm_oid, 
        signatures, 
        session["signature_date"]
    )
    
    signed_document_base64 = response.json()["documentWithSignature"][0]
    
    new_name = add_suffix_to_filename(os.path.basename(file_path))
    print(new_name)    
    mime_type, _ = mimetypes.guess_type(file_path)
    print(mime_type)  
        
    response_json = {
        "document_string": signed_document_base64, 
        "filename": new_name, 
        "content_type": mime_type
    }
    
    os.remove(file_path)
        
    if(session.get("signature_date") is not None):
        session.pop("signature_date")
    if(session.get("form_global") is not None):
        session.pop("form_global")
    if(session.get("credentialChosen") is not None):
        session.pop("credentialChosen")
    if(session.get("credential_access_token") is not None):
        session.pop("credential_access_token")
    if(session.get("hashes") is not None):
        session.pop("hashes")
    if(session.get("certificate_chain") is not None):
        session.pop("certificate_chain")
    if(session.get("end_entity_certificate") is not None):
        session.pop("end_entity_certificate")
    if(session.get("filename") is not None):
        session.pop("filename")
    
    return render_template(
        'sign_document.html',
        redirect_url=cfgserv.service_url, 
        document_signed_value=signed_document_base64,
        document_content_type=mime_type,
        document_filename=new_name
    )
    
def add_suffix_to_filename(filename, suffix="_signed"):
    name, ext = os.path.splitext(filename)
    return f"{name}{suffix}{ext}"