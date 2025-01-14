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

# Function that makes a request to the endpoint /calculate_hash do SCA
# It return a JSON Object with the hash value and the date
def calculate_hash_request(document, signature_format, conformance_level, signed_envelope_property, container, end_entity_certificate,
                           certificate_chain, hash_algorithm_oid):
    url = cfgserv.SCA+"/signatures/calculate_hash"
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    payload = json.dumps({
        "documents": [
            {
                "document": document,
                "signature_format": signature_format,
                "conformance_level": conformance_level,
                "signed_envelope_property": signed_envelope_property,
                "container": container
            }
        ],
        "endEntityCertificate": end_entity_certificate,
        "certificateChain": [
            certificate_chain
        ],
        "hashAlgorithmOID": hash_algorithm_oid
    })

    print(payload)

    response = requests.post(url , headers=headers, data=payload)
    print(response.text)
    
    return response.json()
     
def obtain_signed_document(document, signature_format, conformance_level, signed_envelope_property, container, end_entity_certificate,
                           certificate_chain, hash_algorithm_oid, signatures, date):
    url = cfgserv.SCA+"/signatures/obtain_signed_doc"
    
    headers = {
        'Content-Type': 'application/json'
    }

    payload = json.dumps({
        "documents": [
            {
                "document": document,
                "signature_format": signature_format,
                "conformance_level": conformance_level,
                "signed_envelope_property": signed_envelope_property,
                "container": container
            }
        ],
        "hashAlgorithmOID": hash_algorithm_oid,
        "returnValidationInfo": False,
        "endEntityCertificate": end_entity_certificate,
        "certificateChain": [
            certificate_chain
        ],
        "signatures": signatures,
        "date": date
    })

    print(payload)

    response = requests.post(url, headers=headers, data=payload)

    print(response.text)

    return response
