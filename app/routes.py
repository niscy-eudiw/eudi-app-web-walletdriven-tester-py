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

import os, mimetypes
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory,
    current_app as app, Response
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
def get_relying_party_service():
    request_uri = request.args.get("request_uri")
    client_id = request.args.get("client_id")
    
    response_uri_local, _, hash_algorithm_oid, document_locations = rc.get_request_object_from_rp(request_uri, client_id)
    
    update_session_values("response_uri", response_uri_local)
    update_session_values("hash_algorithm_oid", hash_algorithm_oid)
    update_session_values("documentLocations", document_locations)
    
    return redirect(url_for("tester.service_authentication"))

# starts the authentication process through the /oauth2/authorize and receives the link to the wallet
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
    
    app.logger.info("Received request with code: %s and state: %s", code, state)
    
    if error:
        app.logger.error("Received Error %s: %s", error, error_description)
        return render_template('500.html', error= error+": "+error_description)
    
    code_verifier = session.get("code_verifier")
    if code_verifier is None:
        app.logger.error("Session key 'code_verifier' is missing.")
        return render_template('500.html', error="Session expired or invalid request.")
    
    if code is None:
        app.logger.error("No authorization code received.")
        return render_template('500.html', error="Missing authorization code.")
    
    try:
        app.logger.info("Requesting token with code: "+code+" and code_verifier: "+code_verifier)
        scope, access_token = qc.oauth2_token_request(code, code_verifier) # trades the code for the access token
    except Exception as e:
        app.logger.error("Error during OAuth token request: %s", str(e), exc_info=True)
        return render_template('500.html', error="OAuth token request failed.")
              
    if scope == "service":
        remove_session_values(variable_name="code_verifier")    
        update_session_values(variable_name="service_access_token", variable_value=access_token)
        return redirect(url_for("tester.service_authentication_successful"))
    elif scope == "credential":
        print("Credential Access Token: "+access_token)
        remove_session_values(variable_name="code_verifier")
        update_session_values(variable_name="credential_access_token", variable_value=access_token)
        return redirect(url_for("tester.upload_document"))

@tester.route("/credentials/list", methods=["GET"])
def list_credentials():
    list_credentials_ids = qc.csc_v2_credentials_list(session.get("service_access_token"))
    return render_template('credential.html', redirect_url=cfgserv.service_url, credentials=list_credentials_ids)

@tester.route("/credentials/select", methods=["POST"])
def select_credential():
    credential_id = request.get_json().get("credentialID")
    app.logger.info("Selected credential: "+credential_id)
    update_session_values(variable_name="credentialID", variable_value=credential_id)
    
    app.logger.info("Requesting information about the selected credential.")
    certificates, key_algos = qc.csc_v2_credentials_info(session.get("service_access_token"), credential_id)
    
    update_session_values(variable_name="end_entity_certificate", variable_value=certificates[0])
    update_session_values(variable_name="certificate_chain", variable_value=certificates[1])
    update_session_values(variable_name="key_algos", variable_value=key_algos)
        
    return "success"

@tester.route('/document/select', methods=['GET'])
def select_document():
    remove_session_values("form_global")

    remove_session_values("filepaths")
    remove_session_values("filenames")

    key_algos = session.get("key_algos")
    hash_algos = []
    for algo in key_algos:
        hash_algo = _SIG_OIDS_TO_HASH.get(ObjectIdentifier(algo))
        if hash_algo is not None:
            hash_algos.append({"name":hash_algo.name.upper(), "oid":DIGEST_OIDS.get(hash_algo.name.lower())})

    documentLocations = session.get("documentLocations")
    if documentLocations is not None:
        docs_urls = []
        docs_filenames = []
        docs_filepaths = []
        for loc in documentLocations:
            document, filename = rc.get_document_from_uri(loc['uri'])
            app.logger.info("Document received from the URI.")
            
            saved_file_path, saved_filename  = dm.save_document_with_name(document, filename)
            docs_filenames.append(saved_filename)
            docs_filepaths.append(saved_file_path)
            app.logger.info("Document saved at "+saved_file_path)
                        
            url = cfgserv.service_url+"/document/"+saved_filename
            docs_urls.append(url)
            app.logger.info("Generated an URL to retrieve the document.")

        print(docs_urls)
        docs_infos = list(zip(docs_urls, docs_filenames))
        update_session_values(variable_name="filepaths", variable_value=docs_filepaths)
        update_session_values(variable_name="filenames", variable_value=docs_filenames)
        return render_template('pdf.html', redirect_url= cfgserv.service_url, digest_algorithms=hash_algos, docs_infos=docs_infos)
    else:
        return render_template('select-doc-page.html', redirect_url= cfgserv.service_url, digest_algorithms=hash_algos)

@tester.route('/document/<path:filename>', methods=["GET"])
def serve_document(filename):
    return send_from_directory("documents", filename)

@tester.route("/auth/credential", methods=["POST"])
def credential_authorization():
    documentLocations = session.get("documentLocations")
    if documentLocations is None:
        document = request.files['upload']
        file_path, filename = dm.save_document(document)

        file_path_session = session.get("filepaths")
        if file_path_session is None:
            update_session_values(variable_name="filepaths", variable_value=[file_path])
        else:
            file_path_session.append(file_path)
            update_session_values(variable_name="filepaths", variable_value=file_path_session)

        print(len(session.get("filepaths")))

        filename_session = session.get("filenames")
        if filename_session is None:
            update_session_values(variable_name="filenames", variable_value=[filename])
        else:
            filename_session.append(filename)
            update_session_values(variable_name="filenames", variable_value=filename_session)

        print(len(session.get("filenames")))

    form_local = request.form
    form_global = session.get("form_global")
    if form_global is None:
        form_global = [form_local]
        update_session_values(variable_name="form_global", variable_value=form_global)
    else:
        form_global.append(form_local)
        update_session_values(variable_name="form_global", variable_value=form_global)
    print(len(session.get("form_global")))

    app.logger.info("Successfully saved the options chosen.")
    return Response("Ok", 200)

@tester.route("/auth/credential", methods=["GET"])
def credential_authorization_page():
    filepaths = session.get("filepaths")
    print(len(filepaths))
    filenames = session.get("filenames")
    print(len(filenames))
    forms_list = session.get("form_global")
    print(len(forms_list))

    if len(filepaths) != len(filenames) or len(filepaths) != len(forms_list):
        remove_session_values(variable_name="credentialID")
        remove_session_values(variable_name="end_entity_certificate")
        remove_session_values(variable_name="certificate_chain")
        remove_session_values(variable_name="key_algos")
        remove_session_values(variable_name="filepaths")
        remove_session_values(variable_name="filenames")
        remove_session_values(variable_name="form_global")
        render_template("500.html", error = "Missing information about files to sign. Please try again.")

    docs_content_list = []
    for path in filepaths:
        base64_pdf = dm.get_base64_document(path)
        docs_content_list.append(base64_pdf)

    hash_algorithm_oid = forms_list[0]["algorithm"]
    update_session_values(variable_name="hash_algorithm_oid", variable_value=hash_algorithm_oid)

    print("Number of Documents To Sign: "+ str(len(filenames)))

    hashes_local, signature_date = sc.calculate_hash_request(
        docs_content_list,
        filenames,
        forms_list,
        session.get("end_entity_certificate"),
        session.get("certificate_chain"),
        hash_algorithm_oid
    )
    print("Number of hashes received: "+ str(len(hashes_local)))
    update_session_values(variable_name="hashes", variable_value=hashes_local)
    update_session_values(variable_name="signature_date", variable_value=signature_date)

    hashes_string = ",".join(hashes_local)
    print("Hashes From SCA: "+hashes_string)

    try:
        num_signatures = len(docs_content_list)
        code_verifier_local, location = qc.oauth2_authorize_credential_request(hashes_string, hash_algorithm_oid, session.get("credentialID"), num_signatures)
    except Exception as e:
        return e, 400

    update_session_values(variable_name="code_verifier", variable_value=code_verifier_local)
    return render_template('credential_authorization.html', redirect_url=cfgserv.service_url, location=location,
                           env_var=env_var)

# Requests to the backend servers
@tester.route('/document/sign', methods=['GET'])
def upload_document():
    filepaths = session.get("filepaths")
    filenames = session.get("filenames")
    forms_list = session.get("form_global")
    hash_algorithm_oid = session.get("hash_algorithm_oid")

    print("Number of Files: "+ str(len(filenames)))
    print(session.get("hashes"))

    signatures = qc.csc_v2_signatures_signHash(
        session.get("credential_access_token"),
        session.get("hashes"),
        hash_algorithm_oid, 
        session.get("credentialID"), 
        "1.2.840.10045.2.1"
    )

    docs_content_list = []
    for path in filepaths:
        base64_pdf = dm.get_base64_document(path)
        docs_content_list.append(base64_pdf)

    signed_documents_base64 = sc.obtain_signed_document(
        docs_content_list,
        filenames,
        forms_list,
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
    remove_session_values(variable_name="filenames")
    remove_session_values(variable_name="filepaths")
    
    documentLocations = session.get("documentLocations")
    if documentLocations is None:
        new_filenames = []
        mime_types = []
        print(filepaths)
        print(forms_list)
        for filepath, form in zip(filepaths, forms_list):
            ext = None
            container = form["container"]
            if container == "ASiC-S":
                mime_type = "application/vnd.etsi.asic-s+zip"
                ext = ".zip"
            elif container == "ASiC-E":
                mime_type = "application/vnd.etsi.asic-e+zip"
                ext = ".zip"
            else:
                mime_type, _ = mimetypes.guess_type(filepath)
            mime_types.append(mime_type)
            new_name = add_suffix_to_filename(os.path.basename(filepath), new_ext=ext)
            new_filenames.append(new_name)

        for path in filepaths:
            os.remove(path)

        signed_doc = list(zip(mime_types, signed_documents_base64, new_filenames))

        return render_template(
            'sign_document.html',
            redirect_url=cfgserv.service_url,
            signed_doc=signed_doc
        )
    else:
        # Remove all the files saved
        for path in filepaths:
            os.remove(path)

        signed_envelope_property_list = []
        for form in forms_list:
            signed_envelope_property_list.append(form["packaging"])

        response_uri = session.get("response_uri")
        _ = rc.post_signed_document_response_uri(response_uri, signed_documents_base64, signed_envelope_property_list)
        remove_session_values(variable_name="documentLocations")
        remove_session_values(variable_name="response_uri")
        return render_template('sign_document_success.html', redirect_url=cfgserv.service_url)

def update_session_values(variable_name, variable_value):
    if session.get(variable_name) is not None:
        session.pop(variable_name)
    session[variable_name] = variable_value
    # app.logger.info("Session: "+str(session))

def remove_session_values(variable_name):
    if session.get(variable_name) is not None:
        session.pop(variable_name)

def add_suffix_to_filename(filename, suffix="_signed", new_ext = None):
    name, ext = os.path.splitext(filename)
    
    if new_ext is not None:
        return f"{name}{suffix}{new_ext}"
    
    return f"{name}{suffix}{ext}"