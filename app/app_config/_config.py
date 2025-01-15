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
This config.py contains configuration data.
"""

class ConfService:
    secret_key = "secret_here"

    service_url = "rp_web_page_here"
    AS="qtsp_as_url_here"
    RS="qtsp_rs_url_here"
    SCA="rp_internal_sca_url_here"
    
    oauth_client_id = "client_id_here"
    oauth_client_secret = "client_secret_here"
    oauth_redirect_uri = service_url+"/oauth/login/code"

    alg_oid={
        "SHA256":"1.2.840.113549.1.1.11",
        "SHA384":"1.2.840.113549.1.1.12",
        "SHA512":"1.2.840.113549.1.1.13"
    }