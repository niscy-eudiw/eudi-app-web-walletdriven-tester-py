# Copyright 2024 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
from app_config.config import ConfService as cfgserv
import json
import base64

# Request to Authorization Server

# Function that executes the /oauth2/authorize request
# It can either return a 302 response (to a authentication endpoint or the redirect uri endpoint)
# It can return error
def oauth2_authorize_service_request(code_challenge, code_challenge_method):
    url = cfgserv.AS+"/oauth2/authorize"
    
    params = {
        "response_type":"code",
        "client_id": cfgserv.oauth_client_id,
        "redirect_uri": cfgserv.oauth_redirect_uri,
        "scope":"service",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": "12345678"
    }
    print(url)
    print(params)
    
    response = requests.get(url = url, params = params, allow_redirects = False)
    print(response)
    print(response.text)
    
    return response

def oauth2_authorize_credential_request(code_challenge, code_challenge_method, num_signatures, hashes, hash_algorithm_oid, credential_id):
    url = cfgserv.AS+"/oauth2/authorize?response_type=code&client_id="+cfgserv.oauth_client_id+"&redirect_uri=" + cfgserv.oauth_redirect_uri+"&scope=credential&code_challenge="+code_challenge+"&code_challenge_method="+code_challenge_method+"&state=12345678&numSignatures=1&hashes="+hashes+"&hashAlgorithmOID="+hash_algorithm_oid+"&credentialID="+credential_id
    print(url)
    response = requests.get(url=url, allow_redirects=False)
    print(response.text)
    return response

def oauth2_token_request(code, code_verifier):
    url =  cfgserv.AS+"/oauth2/token"
        
    value_to_encode = f"{cfgserv.oauth_client_id}:{cfgserv.oauth_client_secret}"
    encoded_value = base64.b64encode(value_to_encode.encode()).decode('utf-8')
    authorization_basic = f"Basic {encoded_value}"
    headers= {
        'Authorization': authorization_basic
    }
    
    params = {
        "grant_type":"authorization_code",
        "code": code,
        "client_id": cfgserv.oauth_client_id,
        "redirect_uri": cfgserv.oauth_redirect_uri,
        "code_verifier": code_verifier
    }
    
    response = requests.post(url = url, params = params, headers = headers, allow_redirects = False)
    print(response.text)
    
    return response

# Request to Resource Server
def csc_v2_credentials_list(access_token):
    url =  cfgserv.RS+"/csc/v2/credentials/list"
    
    authorization_header = "Bearer "+access_token
    headers = {
        'Content-Type': 'application/json', 
        'Authorization': authorization_header
    }
    
    payload = json.dumps({
        "credentialInfo": "true",
        "certificates": "single",
        "certInfo": "true"
    })
    
    response = requests.post(url = url, data=payload, headers = headers)  
    print(response)  
    return response

def csc_v2_credentials_info(access_token, credentialId):
    url =  cfgserv.RS+"/csc/v2/credentials/info"
    
    authorization_header = "Bearer "+access_token
    headers = {
        'Content-Type': 'application/json', 
        'Authorization': authorization_header
    }
    
    payload = json.dumps({
        "credentialID": credentialId,
        "credentialInfo": "true",
        "certificates": "chain",
        "certInfo": "true"
    })
    
    response = requests.post(url = url, data=payload, headers = headers)    
    return response

def csc_v2_signatures_signHash(access_token, hashes, hash_algorithm_oid, credential_id, sign_algo):
    url = cfgserv.RS+"/csc/v2/signatures/signHash"
    
    authorization_header = "Bearer "+access_token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': authorization_header
    }

    payload = json.dumps({
        "credentialID": credential_id,
        "hashes": hashes,
        "hashAlgorithmOID": hash_algorithm_oid,
        "signAlgo": sign_algo,
        "operationMode": "S",
        "client_Data": "12345678"
    })
    
    print(payload)
    
    response = requests.post(url, headers=headers, data=payload)
    print(response.text)
    
    return response