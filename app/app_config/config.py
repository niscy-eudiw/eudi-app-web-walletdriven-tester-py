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
This config.py contains configuration data for the age-over-poc Web service. 

NOTE: You should only change it if you understand what you're doing.
"""

import logging
from logging.handlers import TimedRotatingFileHandler
from flask import  session

class ConfService:
    secret_key = "secret_key"

    service_url = "http://127.0.0.1:5000/"
    AS="http://localhost:8084"
    RS="http://localhost:8085"
    SCA="http://localhost:8086"
    
    oauth_client_id = "wallet-client"
    oauth_client_secret = "somesecret2"
    oauth_redirect_uri = "http://127.0.0.1:5000/oauth/login/code"

    alg_oid={
        "SHA256":"1.2.840.113549.1.1.11",
        "SHA384":"1.2.840.113549.1.1.12",
        "SHA512":"1.2.840.113549.1.1.13"
    }