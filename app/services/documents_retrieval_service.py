# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
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
import jwt
import requests
import re
from typing import Tuple, Union
from flask import current_app as app
from werkzeug.datastructures.structures import MultiDict
from app.schemas.document_retrieval import (
    DocumentRetrievalRequestObject, ETSI119432DocumentRetrievalRequestObject, DocumentRetrievalResponse, DocumentRetrievalRequest
)

RequestObject = Union[DocumentRetrievalRequestObject,
                      ETSI119432DocumentRetrievalRequestObject]


def _get_request_data_from_request_uri(request: DocumentRetrievalRequest) -> dict:
    app.logger.info(
        f"Retrieving Request Object from {request.request_uri} (client_id={request.client_id}).")
    response = requests.get(request.request_uri)
    app.logger.debug(
        f"Request Object response: status={response.status_code}, content-type={response.headers.get('Content-Type')}, body={response.text}")
    if response.status_code != 200:
        app.logger.error(
            f"It was impossible to retrieve Request Object from Relying Party: {response.status_code} - {response.text}")
        raise ValueError(
            "It was impossible to retrieve Request Object from Relying Party.")
    app.logger.info(
        "Retrieved the Request Object with document to sign from Relying Party.")
    try:
        return jwt.decode(response.text, options={"verify_signature": False})
    except jwt.exceptions.DecodeError:
        app.logger.exception(
            f"Request Object returned by Relying Party is not a valid JWT: {response.text}")
        raise


def _get_request_data_from_query_params(args: MultiDict[str, str]) -> dict:
    app.logger.info(
        f"Reading Request Object from query parameters: {list(args.keys())}")
    request_data = args.to_dict()
    for key in ("documentDigests", "documentLocations", "dcql_query", "transaction_data"):
        if key in request_data:
            try:
                request_data[key] = json.loads(request_data[key])
            except json.JSONDecodeError:
                app.logger.exception(
                    f"Query parameter '{key}' is not valid JSON: {request_data[key]}")
                raise
    return request_data


def get_request_object(args: MultiDict[str, str]) -> RequestObject:
    if args.get("request_uri"):
        request_data = _get_request_data_from_request_uri(
            DocumentRetrievalRequest(args))
    else:
        request_data = _get_request_data_from_query_params(args)

    app.logger.info(f"Request Object data: {request_data}")

    if "transaction_data" in request_data:
        app.logger.info(
            "Request Object contains transaction_data: parsing as ETSI TS 119 432 request.")
        return ETSI119432DocumentRetrievalRequestObject.from_dict(request_data)
    if "documentLocations" in request_data:
        app.logger.info(
            "Request Object contains documentLocations: parsing as CSC request.")
        return DocumentRetrievalRequestObject.from_dict(request_data)
    raise ValueError(
        "Unrecognized Request Object: missing transaction_data or documentLocations.")


def get_document_locations(request_object: RequestObject) -> dict:
    if isinstance(request_object, ETSI119432DocumentRetrievalRequestObject):
        app.logger.debug(
            f"Decoding transaction_data: {request_object.transaction_data}")
        try:
            signature_requests = []
            for transaction_data in request_object.transaction_data:
                transaction_data_bytes = base64.urlsafe_b64decode(
                    transaction_data + "=" * (-len(transaction_data) % 4))
                transaction_data_json = json.loads(
                    transaction_data_bytes.decode("utf-8"))
                signature_requests.extend(
                    transaction_data_json.get("signatureRequests", []))
            document_locations = {"signatureRequests": signature_requests}
        except Exception:
            app.logger.exception(
                f"Failed to decode transaction_data: {request_object.transaction_data}")
            raise
    else:
        document_locations = {
            "signatureRequests": [
                {"href": location.uri, "responseURI": request_object.response_uri}
                for location in request_object.document_locations
            ]
        }

    app.logger.info(f"Document locations: {document_locations}")
    return document_locations


def post_signed_document_response_uri(response_uri: str, signed_documents: list[str], packagings: list[str],
                                      as_json: bool = False) -> str:
    signature_objects = []
    documents_with_signature = []
    for doc, packaging in zip(signed_documents, packagings):
        if packaging == "DETACHED":
            signature_objects.append(doc)
        else:
            documents_with_signature.append(doc)
    payload = DocumentRetrievalResponse(
        documentWithSignature=documents_with_signature, signatureObject=signature_objects)

    if as_json:
        response = requests.post(url=response_uri, json=payload.to_dict(),
                                 headers={'Content-Type': 'application/json'})
    else:
        response = requests.post(url=response_uri, data=payload.to_dict(),
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
    if response.status_code == 200:
        app.logger.info(
            f"Uploaded signed document to Relying Party {response_uri}")
        return response.text
    else:
        app.logger.error(
            f"It was impossible to upload signed document to Relying Party: {response.text}")
        raise ValueError(
            f"It was impossible to upload signed document to Relying Party: {response.text}")


def post_signed_documents_to_relying_party(document_locations: dict, default_response_uri: str,
                                           signed_documents: list[str], packagings: list[str],
                                           as_json: bool = False) -> None:
    # Signed documents follow the order of signatureRequests. CSC requests share a single
    # response_uri, while ETSI TS 119 432 requests may define one responseURI per signature request.
    signature_requests = document_locations.get("signatureRequests", [])
    if len(signature_requests) != len(signed_documents):
        app.logger.warning(
            f"Number of signature requests ({len(signature_requests)}) differs from number of signed documents ({len(signed_documents)}).")

    grouped = {}
    for signature_request, doc, packaging in zip(signature_requests, signed_documents, packagings):
        response_uri = signature_request.get("responseURI") or default_response_uri
        if not response_uri:
            raise ValueError(
                f"Missing responseURI for signature request: {signature_request.get('href')}")
        docs, packs = grouped.setdefault(response_uri, ([], []))
        docs.append(doc)
        packs.append(packaging)

    for response_uri, (docs, packs) in grouped.items():
        post_signed_document_response_uri(response_uri, docs, packs, as_json)


def get_document_from_uri(document_uri: str) -> Tuple[bytes, str]:
    match = re.search(r'/document/([^/]+)$', document_uri)
    if not match:
        raise ValueError("Invalid URI: Unable to extract filename")
    filename = match.group(1)

    document = requests.get(document_uri, stream=True)

    if document.status_code != 200:
        raise ValueError(f"Failed to get document from URI: {document.text}")

    return document.content, filename