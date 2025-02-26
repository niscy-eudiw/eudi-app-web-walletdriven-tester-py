import requests, jwt, re
from app_config.config import ConfService as cfgserv

algorithm = cfgserv.algorithm

def get_request_object_from_rp(request_uri, client_id):
    jwt_object = requests.get(request_uri)
    print(jwt_object)
    request_object_decoded = jwt.decode(jwt_object.text, algorithm, options={"verify_signature": False})
    
    response_uri = request_object_decoded["response_uri"]
    document_digests = request_object_decoded["documentDigests"]
    hash_algorithm_oid = request_object_decoded["hashAlgorithmOID"]
    document_locations = request_object_decoded["documentLocations"]
    
    return response_uri, document_digests, hash_algorithm_oid, document_locations

def get_filename_from_uri(uri):
    match = re.search(r'/document/([^/]+)$', uri)
    if not match:
        raise ValueError("Invalid URI: Unable to extract filename")
    return match.group(1)

def get_document_from_uri(uri):
    filename = get_filename_from_uri(uri)
    document = requests.get(uri, stream=True)
    
    if document.status_code != 200:
        raise ValueError(f"Failed to get document from URI: {document.text}")
    
    return document.content, filename

def post_signed_document_response_uri(response_uri, signed_document, packaging):
    if packaging == "DETACHED":
        payload = {
            "signatureObject": signed_document
        }
    else:
        payload = {
            "documentWithSignature": signed_document
        }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    print(payload)
    
    response = requests.post(url = response_uri, data=payload, headers = headers)
    
    if response.status_code != 200:
        raise ValueError(f"Failed to post signed document to response URI: {response.text}")
    
    else: 
        print("Successfully upload signed document at: "+response_uri)
        return response.text