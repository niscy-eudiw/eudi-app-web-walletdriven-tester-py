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

import os, base64, base64, mimetypes
from flask import (
    Blueprint,
    render_template,
    request,
    redirect, 
    url_for,
    session,
    send_from_directory,
    current_app as app
)

from app_config.config import ConfService as cfgserv
import app.model.qtsp_client as qc, app.model.sca_client as sc, app.model.rp_client as rc, app.model.documents_manage as dm
from cryptography.x509.oid import _SIG_OIDS_TO_HASH 
from cryptography.hazmat._oid import ObjectIdentifier

tester = Blueprint("tester", __name__, url_prefix="/tester")
tester.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

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

@tester.route('/', methods=['GET'])
def main():
    return render_template('main.html', redirect_url= cfgserv.service_url)

@tester.route("/relying_party_service", methods=["GET"])
def getRelyingPartyService():
    request_uri = request.args.get("request_uri")
    client_id = request.args.get("client_id")
    
    response_uri, _, hashAlgorithmOID, documentLocations = rc.getRequestObjectFromRP(request_uri, client_id)
    
    update_session_values("response_uri", response_uri)
    update_session_values("hash_algorithm_oid", hashAlgorithmOID)
    update_session_values("documentLocations", documentLocations)
    
    return redirect(url_for("tester.service_authentication"))

# starts the authentication process throught the /oauth2/authorize and receives the link to the wallet
@tester.route('/auth/service', methods=['GET'])
def service_authentication():
    app.logger.info("Starting the authentication process.")
    
    try:
       code_verifier_local, location = qc.oauth2_authorize_service_request()
    except Exception as e:
        app.logger.error("Error: "+str(e))
        return str, 400

    update_session_values(variable_name="code_verifier", variable_value=code_verifier_local)

    app.logger.info("Displaying the authentication page.")

    return render_template('auth.html', redirect_url=cfgserv.service_url, env_var=env_var, location=location)

@tester.route("/auth/service/success", methods=["GET", "POST"])
def service_authentication_successful():
    return render_template('auth_success_page.html', redirect_url= cfgserv.service_url, access_token_value=session.get("service_access_token"), env_var=env_var)

# endpoint where the qtsp will be redirected to after authentication
@tester.route("/oauth/login/code", methods=["GET", "POST"])
def oauth_login_code():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description=request.args.get("error_description")
    app.logger.info("Received request with code: "+str(code) + "and state "+str(state))
    if(error is not None):
        app.logger.error("Received Error "+error+": "+error_description)
        return error_description, 400
    
    code_verifier = session.get("code_verifier")
    
    if(code == None):
        return error_description, 400
    
    else:
        try:
            app.logger.info("Requesting token with code: "+code+" and code_verifier: "+code_verifier)
            scope, access_token = qc.oauth2_token_request(code, code_verifier) # trades the code for the access token
        except Exception as e:
            return e, 400
              
        if(scope == "service"):
            # remove_session_values(variable_name="code_verifier")    
            update_session_values(variable_name="service_access_token", variable_value=access_token)
            return redirect(url_for("tester.service_authentication_successful"))
        elif(scope == "credential"):
            # remove_session_values(variable_name="code_verifier")
            update_session_values(variable_name="credential_access_token", variable_value=access_token)
            return redirect(url_for("tester.upload_document"))

@tester.route("/credentials/list", methods=["GET"])
def list_credentials():
    list_credentials_ids = qc.csc_v2_credentials_list(session.get("service_access_token"))
    return render_template('credential.html', redirect_url=cfgserv.service_url, credentials=list_credentials_ids)

@tester.route("/credentials/select", methods=["POST"])
def select_credential():
    credentialId = request.get_json().get("credentialID")
    app.logger.info("Selected credential: "+credentialId)
    update_session_values(variable_name="credentialID", variable_value=credentialId)
    
    app.logger.info("Requesting information about the selected credential.")
    certificates, key_algos = qc.csc_v2_credentials_info(session.get("service_access_token"), credentialId)
    
    update_session_values(variable_name="end_entity_certificate", variable_value=certificates[0])
    update_session_values(variable_name="certificate_chain", variable_value=certificates[1])
    update_session_values(variable_name="key_algos", variable_value=key_algos)
        
    return "success"

@tester.route('/document/select', methods=['GET'])
def select_document():
    key_algos = session.get("key_algos")
    hash_algos = []
    for algo in key_algos:
        hash_algo = _SIG_OIDS_TO_HASH.get(ObjectIdentifier(algo))
        if(hash_algo is not None):
            hash_algos.append({"name":hash_algo.name.upper(), "oid":DIGEST_OIDS.get(hash_algo.name.lower())})
    
    documentLocations = session.get("documentLocations")
    if(documentLocations is not None):
        for loc in documentLocations:
            document, filename = rc.getDocumentFromURI(loc['uri'])
            app.logger.info("Document received from the URI.")
            
            saved_file_path, saved_filename  = dm.save_document_with_name(document, filename)
            session["filepath"] = saved_file_path
            app.logger.info("Document saved at "+saved_file_path)
                        
            url = cfgserv.service_url+"/document/"+saved_filename
            app.logger.info("Generated an URL to retrieve the document.")
        return render_template('pdf.html', redirect_url= cfgserv.service_url, digest_algorithms=hash_algos, mode="view", file_url=url)
    
    else:
        return render_template('pdf.html', redirect_url= cfgserv.service_url, digest_algorithms=hash_algos, mode = "upload")

@tester.route('/document/<path:filename>', methods=["GET"])
def serve_document(filename):
    return send_from_directory("documents", filename)

@tester.route("/auth/credential", methods=["POST"])
def credential_authorization():
    documentLocations = session.get("documentLocations")
    if(documentLocations is None):
        document = request.files['upload']
        filename = dm.save_document(document)
        session["filepath"] = filename
        base64_pdf= base64.b64encode(document.read()).decode("utf-8")
        document.stream.seek(0)
       
    if(documentLocations is not None):
        filename = session.get("filepath")
        base64_pdf = dm.get_base64_document(filename)
        
    form_local= request.form
    container=form_local["container"]
    session["container"] = container
    signature_format= form_local["signature_format"]
    session["signature_format"] = signature_format
    signed_envelope_property= form_local["packaging"]
    session["signed_envelope_property"] = signed_envelope_property 
    conformance_level= form_local["level"]
    session["conformance_level"] = conformance_level
    hash_algorithm_oid= form_local["algorithm"]
    session["hash_algorithm_oid"] = hash_algorithm_oid

    hashes, signature_date = sc.calculate_hash_request(
            base64_pdf,
            signature_format,
            conformance_level,
            signed_envelope_property,
            container,
            session.get("end_entity_certificate"),
            session.get("certificate_chain"),
            hash_algorithm_oid
        )    
    update_session_values(variable_name="hashes", variable_value=hashes)
    update_session_values(variable_name="signature_date", variable_value=signature_date)
    
    hashes_string = ";".join(hashes)
    
    try:
        code_verifier, location = qc.oauth2_authorize_credential_request(hashes_string, hash_algorithm_oid, session.get("credentialID"))
    except Exception as e:
        return e, 400

    update_session_values(variable_name="code_verifier", variable_value=code_verifier)


    return render_template('credential_authorization.html', redirect_url=cfgserv.service_url, location=location, env_var=env_var)

# Requests to the backend servers
@tester.route('/document/sign', methods=['GET'])
def upload_document():
    
    container = session.get("container")
    signature_format = session.get("signature_format")
    signed_envelope_property = session.get("signed_envelope_property")
    conformance_level = session.get("conformance_level")
    hash_algorithm_oid = session.get("hash_algorithm_oid")
    
    file_path = session.get("filepath")
    base64_pdf = dm.get_base64_document(file_path)
    
    signatures = qc.csc_v2_signatures_signHash(
        session.get("credential_access_token"),
        session.get("hashes"),
        hash_algorithm_oid, 
        session.get("credentialID"), 
        "1.2.840.10045.2.1"
    )

    signed_document_base64 = sc.obtain_signed_document(
        base64_pdf, 
        signature_format, 
        conformance_level,
        signed_envelope_property, 
        container, 
        session.get("end_entity_certificate"),
        session.get("certificate_chain"),
        hash_algorithm_oid, 
        signatures, 
        session.get("signature_date")
    )
    
    remove_session_values(variable_name="signature_date")
    remove_session_values(variable_name="form_global")
    remove_session_values(variable_name="credentialID")
    remove_session_values(variable_name="credential_access_token")
    remove_session_values(variable_name="hashes")
    remove_session_values(variable_name="certificate_chain")
    remove_session_values(variable_name="end_entity_certificate")
    remove_session_values(variable_name="filename")
    
    documentLocations = session.get("documentLocations")
    if(documentLocations is None):
        new_name = add_suffix_to_filename(os.path.basename(file_path))
        mime_type, _ = mimetypes.guess_type(file_path)    
    
    os.remove(file_path)
    
    if(documentLocations is not None):
        response_uri = session.get("response_uri")
        _ = rc.postSignedDocumentResponseURI(response_uri, signed_document_base64)
        remove_session_values("documentLocations")
        remove_session_values("response_uri")
        
        return render_template('sign_document_success.html', redirect_url=cfgserv.service_url)
    else:
        return render_template(
            'sign_document.html',
            redirect_url=cfgserv.service_url, 
            document_signed_value=signed_document_base64,
            document_content_type=mime_type,
            document_filename=new_name
        )


def update_session_values(variable_name, variable_value):
    if(session.get(variable_name) is not None):
        session.pop(variable_name)
    session[variable_name] = variable_value
    # app.logger.info("Session: "+str(session))

def remove_session_values(variable_name):
    if(session.get(variable_name) is not None):
        session.pop(variable_name)

def add_suffix_to_filename(filename, suffix="_signed"):
    name, ext = os.path.splitext(filename)
    return f"{name}{suffix}{ext}"