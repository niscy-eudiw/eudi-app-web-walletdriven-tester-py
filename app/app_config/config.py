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
    #service_url = "https://tester.relyingparty.eudiw.dev/"

    metadata_supported_credentials_url="https://issuer.eudiw.dev/.well-known//openid-credential-issuer"

    QTSP_url="http://localhost:8081/"
    SCA="http://localhost:8082/"

    credentials_not_supported=[
        # "eu.europa.ec.eudiw.loyalty_mdoc",
        "eu.europa.ec.eudiw.pseudonym_over18_mdoc_deferred_endpoint"
    ]

    alg_oid={
        "SHA256":"1.2.840.113549.1.1.11",
        "SHA384":"1.2.840.113549.1.1.12",
        "SHA512":"1.2.840.113549.1.1.13"
    }


    # log_dir = "/tmp/log"
    # #log_dir = "../../log"
    # log_file_info = "logs.log"

    # backup_count = 7

    # log_handler_info = TimedRotatingFileHandler(
    #     filename=f"{log_dir}/{log_file_info}",
    #     when="midnight",  # Rotation midnight
    #     interval=1,  # new file each day
    #     backupCount=backup_count,
    # )

    # log_handler_info.setFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")

    # logger_info = logging.getLogger("info")
    # logger_info.addHandler(log_handler_info)
    # logger_info.setLevel(logging.INFO)