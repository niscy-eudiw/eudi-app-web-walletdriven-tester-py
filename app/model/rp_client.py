import requests, jwt, re, json

from app_config.config import ConfService as cfgserv

algorithm = cfgserv.algorithm

def getRequestObjectFromRP(request_uri, client_id):
    
    jwt_object = requests.get(request_uri)
    print(jwt_object)
    request_object_decoded = jwt.decode(jwt_object.text, algorithm, options={"verify_signature": False})
    
    response_uri_l = request_object_decoded["response_uri"]
    documentDigests = request_object_decoded["documentDigests"]
    hashAlgorithmOID_l = request_object_decoded["hashAlgorithmOID"]
    documentLocations_l = request_object_decoded["documentLocations"]
    
    return response_uri_l, documentDigests, hashAlgorithmOID_l, documentLocations_l

def getFilenameFromURI(uri):
    match = re.search(r'/document/([^/]+)$', uri)
    if not match:
        raise ValueError("Invalid URI: Unable to extract filename")
    return match.group(1)

def getDocumentFromURI(uri):
    filename = getFilenameFromURI(uri)
    document = requests.get(uri, stream=True)
    
    if document.status_code != 200:
        raise ValueError(f"Failed to get document from URI: {document.text}")
    
    return document.content, filename

def postSignedDocumentResponseURI(response_uri, signed_document):   
    payload = json.dumps({
        "documentWithSignature": signed_document
    })
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    print(payload)
    
    response = requests.post(url = response_uri, data=payload, headers = headers)
    
    if response.status_code != 200:
        raise ValueError(f"Failed to post signed document to response URI: {response.text}")
    
    else: 
        print("Successfully upload signed document at: "+response_uri)
        return response.text