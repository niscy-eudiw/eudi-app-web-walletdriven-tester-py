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

from app_config.config import ConfService as cfgserv

from app_config.config import ConfService as cfgserv

sca = Blueprint("SCA", __name__, url_prefix="/")

sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')


# @sca.route('/', methods=['GET','POST'])
# def initial_page():
#     credential_list=dict()
#     for credential in oidc_metadata["credentials_supported"]:
#         name=oidc_metadata["credentials_supported"][credential]["display"][0]["name"]
#         format=oidc_metadata["credentials_supported"][credential]["format"]
#         full_name= name + f" ({format})"
#         credential_list.update({full_name:credential})

#     return render_template('initial_page.html', redirect_url= cfgserv.service_url, credential_list=credential_list)

# @sca.route('/select_credential', methods=['GET','POST'])
# def select_credential():

#     choice= request.form.get("optionsRadios")

#     credentialsSupported = oidc_metadata["credentials_supported"]

#     for namespaces in credentialsSupported[choice]["claims"]:
#         doctype= namespaces

#     if "jwt_vc_json" in choice:
#             attributes_req,optional = getMandatoryAttributes(
#                             credentialsSupported[choice]["claims"]
#                         )
#     else:
#         attributes_req, optional = getMandatoryAttributes(
#                         credentialsSupported[choice]["claims"][doctype]
#                     )
    
#     session["credential"]=choice
            

#     return render_template('metadata_form.html', attributes=attributes_req, optional=optional)
@sca.route('/select_pdf', methods=['GET','POST'])
def select_pdf():

    return render_template('pdf.html', redirect_url= cfgserv.service_url)

@sca.route('/upload_document', methods=['GET','POST'])
def upload_document():

    oid_alg=cfgserv.alg_oid

    document= request.files['upload']

    form= request.form

    container=form["container"]

    signature_format= form["signature_format"]

    packaging= form["packaging"]

    level= form["level"]

    digest_algorithm= form["algorithm"]

    base64_pdf= base64.b64encode(document.read()).decode("utf-8")

    headers ={
        "Content-Type": "application/json",
        'Authorization': 'Bearer test',
    }

    payload = {
        "sad": "sad_for_cred1",
        "credentialID": "cred1",
        "documents":[{
            
            "document":base64_pdf,
            # "hashes":"hashes array",
            # "hashAlgorithmOID": "hash OID",
            "signature_format":signature_format[0],
            "conformance_level": level,
            "signed_envelope_property":packaging,
            "signAlgo":oid_alg[digest_algorithm],
            "operationMode":"S"
            # "signAlgoParams":"Base64-encoded DER-encoded ASN.1 signature parameters"
        }],
        "request_uri":"http://localhost:8081",
        "clientData": "12345678"

    }

    return payload
    #return jsonify(payload)
    response = requests.request("POST", cfgserv.SCA + "signatures/signDoc" , headers=headers, data=json.dumps(payload))

    # if response.status_code != 200:
    #     log.logger_error.error("Authorization endpoint invalid request")
    # return auth_error_redirect(redirect_uri,"invalid_request")

    response = response.json()
    with open(os.path.join("app\pdfs","test.pdf"), "wb") as f:
        f.write(base64.b64decode(response["documentWithSignature"][0]))
    
    return response["documentWithSignature"][0]
    
