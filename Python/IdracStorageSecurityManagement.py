""" Python script using Redfish API with OEM extension to enable SEKM/iLKM solutions

Copyright (c) 2022, Dell, Inc.

This software is licensed to you under the GNU General Public License,
version 2 (GPLv2). There is NO WARRANTY for this software, express or
implied, including the implied warranties of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
along with this software; if not, see
https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

__version__ = "1.0"
__license__ = "GPLv2"
__authors__ = ["Fadi Hanna Al-Kass", "Xavier Conley", "Aaron Colichia"]
__copyright__ = "Copyright (c) 2022, Dell, Inc"

__maintainer__ = "Xavier Conley"
__email__ = "Xavier_Conley (at) Dell (dot) com"
"""

import argparse
import configparser
import json
import os
import sys
import time
from copy import deepcopy
from datetime import datetime
from time import sleep

import requests
import urllib3

urllib3.disable_warnings()

# script constants
CWD = os.getcwd()
INI_KMS_SECTION = "key_management_server_attributes"
INI_IDRAC_KMS_SECTION = "idrac_kms_attributes"
INI_IDRAC_SEKMCERT_SECTION = "idrac_sekmcert_attributes"
INI_IDRAC_SEKM_SECTION = "idrac_sekm_attributes"
INI_STORAGE_SECTION = "storage"
STORAGE_SUPPORTED_CONTROLLERS = "supported_storage_controllers"
KMIP_SERVERADDRESS = "KMIP_ServerAddress"
KMIP_PORTNUMBER = "KMIPPortNumber"
KMIP_SERVERUSERNAME = "KMIP_ServerUsername"
KMIP_SERVERPASSWORD = "KMIP_ServerPassword"

# idrac constants
KMS_SERVER_CA = 'KMS_SERVER_CA'
SEKM_SSL_CERT = 'SEKM_SSL_CERT'
KMS_IDRACUSERNAME = "iDRACUserName"
KMS_IDRACPASSWORD = "iDRACPassword"
KMS_KMIPPORTNUMBER = "KMIPPortNumber"
KMS_PRIMARYSERVERADDRESS = "PrimaryServerAddress"
KMS_REDUNDANTKMIPPORTNUMBER = "RedundantKMIPPortNumber"
KMS_REDUNDANTSERVERADDRESS1 = "RedundantServerAddress1"
KMS_REDUNDANTSERVERADDRESS2 = "RedundantServerAddress2"
KMS_REDUNDANTSERVERADDRESS3 = "RedundantServerAddress3"
KMS_REDUNDANTSERVERADDRESS4 = "RedundantServerAddress4"
KMS_REDUNDANTSERVERADDRESS5 = "RedundantServerAddress5"
KMS_REDUNDANTSERVERADDRESS6 = "RedundantServerAddress6"
KMS_REDUNDANTSERVERADDRESS7 = "RedundantServerAddress7"
KMS_REDUNDANTSERVERADDRESS8 = "RedundantServerAddress8"
KMS_TIMEOUT = "Timeout"
SEKMCERT_COMMONNAME = "CommonName"
SEKMCERT_COUNTRYCODE = "CountryCode"
SEKMCERT_EMAILADDRESS = "EmailAddress"
SEKMCERT_LOCALITYNAME = "LocalityName"
SEKMCERT_ORGANIZATIONNAME = "OrganizationName"
SEKMCERT_ORGANIZATIONUNIT = "OrganizationUnit"
SEKMCERT_STATENAME = "StateName"
SEKMCERT_SUBJECTALTNAME = "SubjectAltName"
SEKMCERT_USERID = "UserId"
SEKM_IPADDRESSINCERTIFICATE = "IPAddressInCertificate"
SEKM_KMSKEYPURGEPOLICY = "KMSKeyPurgePolicy"
SEKM_AUTOSECURE = "SEKM.1.AutoSecure"
SEKM_ILKMSTATUS = "SEKM.1.iLKMStatus"
SEKM_SETSTATE = "SEKM.1.SetState"
SEKM_SEKMSTATUS = "SEKM.1.SEKMStatus"
ENABLE = "Enable"
ENABLED = "Enabled"
DISABLE = "Disable"
DISABLED = "Disabled"


def generate_template_ini():
    """
    Create an ini file in the current working directory with the required params in a template
    :return: str, full path to the generated file
    """
    filename = 'idrac_storage_security_management-template.ini'
    template = configparser.ConfigParser()
    template.add_section(INI_KMS_SECTION)
    template.set(INI_KMS_SECTION, KMIP_SERVERADDRESS, "<KMS IP ADDRESS>")
    template.set(INI_KMS_SECTION, KMIP_PORTNUMBER, "5696")
    template.set(INI_KMS_SECTION, KMIP_SERVERUSERNAME, "<KMS USERNAME>")
    template.set(INI_KMS_SECTION, KMIP_SERVERPASSWORD, "<KMS PASSWORD>")
    template.add_section(INI_IDRAC_KMS_SECTION)
    template.set(INI_IDRAC_KMS_SECTION, KMS_IDRACUSERNAME, "<IDRAC USERNAME>")
    template.set(INI_IDRAC_KMS_SECTION, KMS_IDRACPASSWORD, "<IDRAC PASSWORD>")
    template.set(INI_IDRAC_KMS_SECTION, KMS_KMIPPORTNUMBER, "5696")
    template.set(INI_IDRAC_KMS_SECTION, KMS_PRIMARYSERVERADDRESS, "<KMS IP ADDRESS>")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTKMIPPORTNUMBER, "5696")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS1, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS2, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS3, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS4, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS5, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS6, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS7, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS8, "")
    template.set(INI_IDRAC_KMS_SECTION, KMS_TIMEOUT, "10")
    template.add_section(INI_IDRAC_SEKMCERT_SECTION)
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_COMMONNAME, "<IDRAC NAME>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_COUNTRYCODE, "<CONTRY CODE>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_EMAILADDRESS, "<EMAIL ADDRESS>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_LOCALITYNAME, "<CITY>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_ORGANIZATIONNAME, "<ORGANIZATION>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_ORGANIZATIONUNIT, "<ORGANIZATION UNIT>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_STATENAME, "<STATE NAME>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_SUBJECTALTNAME, "<KMS IP ADDRESS>")
    template.set(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_USERID, "<IDRAC NAME>")
    template.add_section(INI_IDRAC_SEKM_SECTION)
    template.set(INI_IDRAC_SEKM_SECTION, SEKM_IPADDRESSINCERTIFICATE, "Disabled")
    template.set(INI_IDRAC_SEKM_SECTION, SEKM_KMSKEYPURGEPOLICY, "Keep All Keys")
    template.add_section(INI_STORAGE_SECTION)
    template.set(INI_STORAGE_SECTION, STORAGE_SUPPORTED_CONTROLLERS, "<CONTROLLER FQDD1, CONTROLLER FQDD2>")

    with open(filename, 'w') as configfile:
        template.write(configfile)
    print(f'INFO: Wrote template ini file {filename}')
    return os.path.join(CWD, filename)


def request(url, request_type="GET", payload=None, auth=None, headers=None, success_codes=None, case_info=None,
            stream=False):
    """
    Wrap requests with common script logic
    :param url:
    :param request_type:
    :param payload:
    :param auth:
    :param headers:
    :param success_codes:
    :param case_info:
    :param stream:
    :return:
    """
    if not payload:
        payload = {}
    if not headers:
        headers = {}
    if not success_codes:
        success_codes = []
    success_codes.append(200)
    content_type = headers.get('content-type')
    json_data_msg = ""
    if content_type == 'application/json':
        payload = json.dumps(payload)
    if not case_info:
        case_info = f"performing {request_type} request"
    if request_type.lower() == 'post':
        response = requests.post(url, data=payload, auth=auth, headers=headers, verify=False)
    elif request_type.lower() == 'patch':
        response = requests.patch(url, data=payload, auth=auth, headers=headers, verify=False)
    elif request_type.lower() == 'get':
        response = requests.get(url, headers=headers, verify=False, auth=auth, stream=stream)
    else:
        print(f'ERROR: This wrapper does not support request type "{request_type} only post, get, and patch."')
        sys.exit(1)

    if not payload:
        payload_msg = ""
    else:
        payload_msg = f'with payload {payload}'

    status_code = response.status_code
    headers = response.headers
    if headers.get('content-type') == 'application/json':
        json_data_msg = f'\njson data: {response.json()}'

    if status_code in success_codes:
        if args.get('debug'):
            print(
                f'DEBUG: {case_info} resulted in status code {status_code} for {request_type} request to {url} {payload_msg}{json_data_msg}')
        return response
    else:
        print(
            f'ERROR: {case_info} resulted in status code {status_code} for {request_type} request to {url} {payload_msg}{json_data_msg}')
        sys.exit(1)


def redfish_get_value_for_property(uri, username, password, property_name):
    """
    Generic get on a value given a property name and uri to interface implementing Redfish (or any restful API that uses
    a JSON payload/entity model over HTTP)
    :param uri: full uri to collection endpoint
    :param username:
    :param password:
    :param property_name: the property to get the value for
    :return: str, the value for the property
    """
    parent_name = uri.rsplit('/', 1)[-1]
    attribute_uri = f'{uri}?$select={property_name}'
    response = request(attribute_uri, 'GET', headers={'content-type': 'application/json'},
                       case_info=f'getting a value for {property_name}', auth=(username, password))
    data = response.json()
    return data.get(parent_name).get(property_name, {})


class ThalesServerFacade:
    """
    KMS server class
    """

    def __init__(self, config=None):
        if not config:
            self.config = object
        else:
            self.config = config
        self.kms_url = f"https://{self.config.kmip_attributes.get(KMIP_SERVERADDRESS)}/api/v1"
        self.kms_user = self.config.kmip_attributes.get(KMIP_SERVERUSERNAME)
        self.kms_pass = self.config.kmip_attributes.get(KMIP_SERVERPASSWORD)
        self.ca_certificate_path = os.path.join(CWD, "local_ca.pem")
        self.signed_sekm_cert = os.path.join(CWD, "signed_sekm_cert.pem")
        self.ca_id = None
        self.bearer_token = None
        self.server_info = None
        self.kms_data = None

    def __get_token(self):
        """"
        Get a valid bearer token.
        """
        if self.bearer_token:
            return self.bearer_token

        response = request(f'{self.kms_url}/auth/tokens', "POST",
                           payload={"username": self.kms_user, "password": self.kms_pass})
        bearer_token = json.loads(response.content.decode("utf-8")).get("jwt")

        if bearer_token is not None:
            print("INFO: The script received a token to authenticate with the key management server.")
            return bearer_token
        else:
            print("ERROR: The script did not receive a token to authenticate with the key management server.")
            sys.exit(1)

    def request(self, path, request_type="GET", payload=None, success_codes=None, case_info=None, stream=False):
        """
        Wrap main request with logic for this class
        :param path:
        :param request_type:
        :param payload:
        :param success_codes:
        :param case_info:
        :param stream:
        :return:
        """
        if not success_codes:
            success_codes = []
        if not self.bearer_token:
            self.bearer_token = self.__get_token()
        headers = {"Authorization": f"Bearer {self.bearer_token}"}
        return request(f'{self.kms_url}/{path.lstrip("/")}', request_type=request_type, payload=payload,
                       headers=headers, success_codes=success_codes, case_info=case_info, stream=stream)

    def get_server_info(self):
        """
        Grab the basic KMS server info
        :return:
        """
        response = self.request('system/info', 'GET')
        kms_data = response.json()
        print("INFO: Key management server is: {}".format(kms_data["model"]))
        print("INFO: Key management server version is: {}".format(kms_data["version"]))
        return kms_data

    def create_and_get_user_info(self, username):
        """
        Get iDRAC user on KMS
        :return:
        """
        limit_parameter = "?limit=100"
        name_parameter = f'?name={username}'

        response = self.request(f'usermgmt/users/{limit_parameter}')
        user_data = response.json()

        user_list = [resource.get('username') for resource in user_data.get('resources', {}) if 'username' in resource]

        if username not in user_list:

            print("INFO: iDRAC user does not exist on this key management server, creating one.")

            user_attributes = {
                "app_metadata": {},
                "email": self.config.sekmcert_attributes.get(f'SEKMCert.1.{SEKMCERT_EMAILADDRESS}'),
                "name": self.config.sekmcert_attributes.get(f'SEKMCert.1.{SEKMCERT_COMMONNAME}'),
                "username": self.config.kms_attributes.get(f'KMS.1.{KMS_IDRACUSERNAME}'),
                "password": self.config.kms_attributes.get(f'KMS.1.{KMS_IDRACPASSWORD}'),
                "user_metadata": {}
            }

            response = self.request('usermgmt/users', 'POST', payload=user_attributes, success_codes=[201, 409],
                                    case_info='creating iDRAC user')

            if response.status_code == 201:
                print("INFO: New iDRAC user was successfully created.")
            elif response.status_code == 409:
                print("INFO: iDRAC user already exists on this key management server.")

        else:
            print("INFO: iDRAC user already exists on the key management server.")

        response = self.request(f'usermgmt/users/{name_parameter}')
        kms_user_data = response.json()
        return kms_user_data

    def add_user_to_key_user_group(self, kms_user_data):
        """
        Add a user to the key users group
        :param kms_user_data:
        :return:
        """

        kms_user_id = \
            [resource.get('user_id') for resource in kms_user_data.get('resources', {}) if 'user_id' in resource][
                0]
        username = \
            [resource.get('username') for resource in kms_user_data.get('resources', {}) if 'username' in resource][
                0]
        _ = self.request(f'usermgmt/groups/Key Users/users/{kms_user_id}', 'POST',
                         case_info=f'adding iDRAC user {username} to Key Users group')
        print(f'INFO: iDRAC user {username} was successfully added to the Key Users group.')

    def get_ca_cert(self):
        """
        Get the local ca certificate information for the KMS server
        :return:
        """
        path = "ca/local-cas?issuer=/C=US/ST=MD/L=Belcamp/O=Gemalto/CN=KeySecure Root CA"

        response = self.request(path, 'GET', case_info='getting KeySecure root ca info')
        data = response.json()

        resources = data.get("resources")
        ca_cert = resources[0].get('cert')
        self.ca_id = resources[0].get('id')
        with open(self.ca_certificate_path, 'wb') as f:
            f.write(ca_cert.encode("utf-8"))
        f.close()
        return self.ca_certificate_path

    def get_signed_cert(self, unsigned_idrac_cert):
        """
        Sign a given CSR and return the signed certificate
        :param unsigned_idrac_cert:
        :return:
        """
        signed_cert = None
        payload = {
            "csr": unsigned_idrac_cert,
            "purpose": "client",
            "duration": 365
        }

        print("INFO: Getting the SEKM SSL certificate signed by the Local Certificate Authority...")
        try:
            response = self.request(f'ca/local-cas/{self.ca_id}/certs', 'POST', payload=payload,
                                    case_info='sign certificate with local CA', success_codes=[201])
            sign_cert_resp_dict = json.loads(response.content.decode("utf-8"))

            if sign_cert_resp_dict and sign_cert_resp_dict.get("cert"):
                signed_cert = sign_cert_resp_dict.get("cert")

        except Exception as e:
            print("ERROR: Failed to decode csr signing response: {}".format(e))
            sys.exit(1)

        if signed_cert is not None:
            print(
                "INFO: Successfully got the SEKM SSL certificate signed by a Certificate Authority on the Key Management Server.")
        else:
            print(f"ERROR: Unable to get the SEKM SSL certificate signed. The response is: {response}")
            sys.exit(1)

        with open(os.path.join(CWD, self.signed_sekm_cert), 'wb') as f:
            f.write(signed_cert.encode("utf-8"))
        f.close()
        return os.path.join(CWD, self.signed_sekm_cert)


class IdracFacade:
    """
    Wrapper class for the iDRAC
    """

    def __init__(self, config=None):
        if not config:
            self.config = object
        else:
            self.config = config
        self.idrac_url = f'https://{idrac_ip}'
        self.username = idrac_username
        self.password = idrac_password
        self.idrac_attributes_url = f'{self.idrac_url}/redfish/v1/Managers/iDRAC.Embedded.1/Attributes'
        self.dell_idrac_manager_url = f'{self.idrac_url}/redfish/v1/Dell/Managers/iDRAC.Embedded.1'
        self.idrac_manager_url = f'{self.idrac_url}/redfish/v1/Managers/iDRAC.Embedded.1'
        self.dell_system_url = f'{self.idrac_url}/redfish/v1/Dell/Systems/System.Embedded.1'
        self.system_url = f'{self.idrac_url}/redfish/v1/Systems/System.Embedded.1'
        self.lc_attributes_url = f'{self.idrac_url}/redfish/v1/Managers/LifecycleController.Embedded.1/Attributes'
        self.system_attributes_url = f'{self.idrac_url}/redfish/v1/Managers/System.Embedded.1/Attributes'
        self.idrac_card_service_url = f'{self.idrac_manager_url}/Oem/Dell/DelliDRACCardService'

        self.enable_idrac_sekm_attribute = {
            SEKM_SETSTATE: ENABLE
        }
        self.disable_idrac_sekm_attribute = {
            SEKM_SETSTATE: DISABLE
        }

        self.job_id = None
        self.csr_filename = 'sekm.csr'
        self.generated_csr = None

    def __get_job_id_from_accepted_response(self, response):
        location = response.headers.get('Location')
        if not location or '/' not in location:
            print(f'ERROR: unable to locate job ID in JSON headers output {response.headers}')
            sys.exit(1)
        return response.headers.get('Location').split("/")[-1]

    def request(self, path, request_type="GET", payload=None, success_codes=None, case_info=None, stream=False):
        """
        Wrap main request with logic for this class
        :param path:
        :param request_type:
        :param payload:
        :param success_codes:
        :param case_info:
        :param stream:
        :return:
        """
        if not success_codes:
            success_codes = []
        headers = {'content-type': 'application/json'}
        if 'http' not in path:
            path = f'{self.idrac_url}/{path.lstrip("/")}'
        return request(path, request_type=request_type, payload=payload, headers=headers,
                       success_codes=success_codes, case_info=case_info, auth=(self.username, self.password),
                       stream=stream)

    def verify_idrac_attribute_matches_expected(self, attribute, expected_value):
        """
        :param attribute: Attribute path relative to self.idrac_attributes_url Eg. SEKM.1.SEKMStatus
        :param expected_value:
        :return:
        """
        f'INFO: Verifying {attribute} has value {expected_value}'
        current_value = redfish_get_value_for_property(self.idrac_attributes_url, self.username, self.password,
                                                       property_name=attribute)
        if current_value != expected_value:
            print(
                f'ERROR: Current value for {attribute} is {current_value}, expected {expected_value}')
            sys.exit(1)
        else:
            print(
                f'INFO: Current value for {attribute} matches expected {expected_value}')
            return True

    def set_sekmcert_attributes(self):
        """
        Set values for the SEKMCert iDRAC attributes
        :return:
        """
        print(f"INFO: Modifying iDRAC with the SEKM certificate attributes: {self.config.sekmcert_attributes}")
        self.request(self.idrac_attributes_url, 'PATCH', payload={'Attributes': self.config.sekmcert_attributes},
                     case_info='modifying SEKM certificate attributes')
        print("INFO: Attributes modified successfully.")

    def generate_csr(self):
        """
        Generate the CSR on the iDRAC and return the string
        :return: generated CSR str
        """
        path = f'{self.dell_idrac_manager_url}/DelliDRACCardService/Actions/DelliDRACCardService.GenerateSEKMCSR'
        success_codes = [202]
        response = self.request(path, 'POST', payload={}, case_info='generating CSR', success_codes=success_codes)
        csr_uri = response.headers.get('Location')
        status_code = response.status_code
        data = response.json()
        if status_code in success_codes:
            print(
                f'INFO: status code {status_code} returned for POST command to generate SEKM CSR. SEKM CSR URI: "{csr_uri}"')
        else:
            print(
                f'ERROR: status code {status_code} returned for POST command to generate SEKM CSR, detail error info: "{csr_uri}"')
            sys.exit(1)

        response = self.request(csr_uri, 'GET', case_info='get request on generated CSR', success_codes=success_codes,
                                stream=True)
        status_code = response.status_code
        if status_code not in success_codes:
            print(
                f'ERROR: status code {status_code} returned for GET command to get generated CSR, detail error info: {data}')
            sys.exit(1)
        with open(os.devnull, 'wb') as devnull:
            devnull.write(response.content)

        self.generated_csr = response.__dict__['_content'].decode('utf-8')
        return self.generated_csr

    def import_certificate(self, cert_type, file_path):
        """
        Upload a certificate to the iDRAC
        :param cert_type:
        :param file_path:
        :return:
        """
        success_codes = [202]
        try:
            with open(file_path, 'r') as f:
                certificate = f.read()
        except EnvironmentError:
            print(f"ERROR: problem reading file {file_path}")

        url = f'{self.dell_idrac_manager_url}/DelliDRACCardService/Actions/DelliDRACCardService.ImportCertificate'
        payload = {"CertificateType": cert_type, "CertificateFile": certificate}
        _ = self.request(url, 'POST', payload=payload, case_info=f'uploading certificate with type {cert_type}',
                         success_codes=success_codes)
        print(f"INFO: Successfully uploaded the SEKM Certificate with type {cert_type} to iDRAC.")

    def set_kms_attributes(self):
        scrubbed_attributes = deepcopy(self.config.kms_attributes)
        scrubbed_attributes.update({f'KMS.1.{KMS_IDRACPASSWORD}': '********'})

        print(f"INFO: Setting iDRAC KMS attributes to {scrubbed_attributes}")
        self.request(self.idrac_attributes_url, 'PATCH', payload={'Attributes': self.config.kms_attributes},
                     case_info='modifying iDRAC KMS attributes')
        print("INFO: Attributes modified successfully.")

    def set_sekm_attributes(self):
        print(f"INFO: Setting iDRAC SEKM attributes to {self.config.sekm_attributes}")
        self.request(self.idrac_attributes_url, 'PATCH', payload={'Attributes': self.config.sekm_attributes},
                     case_info='modifying iDRAC SEKM attributes')
        print("INFO: Attributes modified successfully.")

    def enable_idrac_sekm(self):
        print("INFO: Enabling SEKM on iDRAC")
        _ = self.request(self.idrac_attributes_url, 'PATCH',
                         payload={'Attributes': self.enable_idrac_sekm_attribute},
                         case_info='modifying iDRAC SEKM status attribute')
        print(f'INFO: Attribute modified successfully')
        sleep(5)
        self.verify_idrac_attribute_matches_expected(SEKM_SEKMSTATUS, ENABLED)

    def enable_idrac_ilkm(self, key_id, key_passphrase):
        url = f'{self.idrac_card_service_url}/Actions/DelliDRACCardService.EnableiLKM'
        payload = {'KeyID': key_id, 'Passphrase': key_passphrase}
        print(f'INFO: Enabling iLKM on iDRAC with key id {key_id}.')
        response = self.request(url, 'POST', payload=payload, case_info=f'enabling iLKM on iDRAC using key {key_id}',
                                success_codes=[202])
        if response.status_code == 202:
            print(f'INFO: Enable iLKM action submitted successfully')
            self.job_id = self.__get_job_id_from_accepted_response(response)
            print(f'INFO: Job ID {self.job_id} successfully created')
            self.wait_for_job(self.job_id)
            sleep(5)
            self.verify_idrac_attribute_matches_expected(SEKM_ILKMSTATUS, ENABLED)
        else:
            print(f'ERROR: Did not expect a "response.status_code" status_code in the response')
            sys.exit(1)

    def set_idrac_autosecure(self, value):
        autosecure_attribute = {
            SEKM_AUTOSECURE: value
        }
        print(f'INFO: Setting AutoSecure value to "{value}" on iDRAC')
        _ = self.request(self.idrac_attributes_url, 'PATCH',
                         payload={'Attributes': autosecure_attribute},
                         case_info='modifying iDRAC AutoSecure status attribute')
        print(f'INFO: Attribute modified successfully')
        sleep(5)
        self.verify_idrac_attribute_matches_expected(SEKM_AUTOSECURE, value)

    def get_idrac_autosecure(self):
        return redfish_get_value_for_property(self.idrac_attributes_url, self.username, self.password, SEKM_AUTOSECURE)

    def get_idrac_ilkm(self):
        return redfish_get_value_for_property(self.idrac_attributes_url, self.username, self.password, SEKM_ILKMSTATUS)

    def enable_controller_sekm_and_get_job_id(self, wait_for_job=True):

        for controller in self.config.controllers:

            controller_uri = f'{self.system_url}/Storage/{controller}'
            enable_action = "DellRaidService.EnableControllerEncryption"
            enable_encryption_uri = f'{self.dell_system_url}/DellRaidService/Actions/{enable_action}'
            response = self.request(controller_uri, "GET", case_info=f"getting controller info for {controller}")
            data = response.json()
            if data.get('Oem').get('Dell', {}).get('DellController', {}).get('SecurityStatus',
                                                                             {}) == 'EncryptionNotCapable':
                print(f"ERROR: storage controller {controller} does not support encryption")
                sys.exit(1)
            else:
                pass
            payload = {"Mode": "SEKM", "TargetFQDD": controller}
            response = self.request(enable_encryption_uri, "POST", payload=payload,
                                    case_info='enabling controller encryption', success_codes=[202])
            if response.status_code == 202:
                print(f'INFO: POST command passed to enable controller encryption for controller {controller}')
                self.job_id = self.__get_job_id_from_accepted_response(response)
                print(f'INFO: Job ID {self.job_id} successfully created for storage action "{enable_action}"')
                if wait_for_job:
                    self.wait_for_job(self.job_id)
                    self.verify_controller_securitystatus_matches_expected(controller,
                                                                           self.config.securitystatus_enabled)
                return self.job_id

    def verify_controller_securitystatus_matches_expected(self, controller, expected_value):
        '''
        Compare the given controller's SecurityStatus attribute with the given expected value
        :param controller: controller fqdd str
        :param expected_value: str
        :return:
        '''
        controller_uri = f'{self.system_url}/Storage/{controller}'
        response = self.request(controller_uri, 'GET', case_info=f'verifying key assigned to {controller}')
        data = response.json()
        current_value = data.get('Oem').get('Dell', {}).get('DellController', {}).get('SecurityStatus', {})
        if current_value == expected_value:
            print(f'PASS: encryption enabled for storage controller {controller}')
        else:
            print(
                f'FAIL: encryption not enabled for storage controller {controller}, current security status is "{current_value}"')
            sys.exit(1)

    def wait_for_job(self, job_id):
        '''
        Monitor job with timeout
        :param job_id: str
        :return:
        '''
        start_time = datetime.now()
        print(f'INFO: waiting for job {job_id}')
        while True:
            response = self.request(f'{self.idrac_manager_url}/Jobs/{job_id}', 'GET',
                                    case_info=f'getting job info for {job_id}')
            current_time = (datetime.now() - start_time)
            data = response.json()
            message = data.get('Message')
            job_state = data.get('JobState')
            if str(current_time)[0:7] >= "2:00:00":
                print("ERROR: Timeout of 2 hours has been hit, script stopped")
                sys.exit(1)
            elif "fail" in message.lower() or job_state == "Failed":
                print(f'ERROR: job ID {job_id} failed, failed message is: {message}')
                sys.exit(1)
            elif job_state == "Completed":
                print("INFO: Final Detailed Job Status Results")
                for i in data.items():
                    if "odata" in i[0] or "MessageArgs" in i[0] or "TargetSettingsURI" in i[0]:
                        pass
                    else:
                        print(f'{i[0]}: {i[1]}')
                break
            else:
                print(f'INFO: JobStatus not completed, current status: "{message}", job state "{job_state}"')
                time.sleep(3)


class SolutionScriptConfig:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read(args["c"])

        self.kmip_attributes = {
            KMIP_SERVERADDRESS: config.get(INI_KMS_SECTION, KMIP_SERVERADDRESS),
            KMIP_SERVERUSERNAME: config.get(INI_KMS_SECTION, KMIP_SERVERUSERNAME),
            KMIP_SERVERPASSWORD: config.get(INI_KMS_SECTION, KMIP_SERVERPASSWORD),
            KMIP_PORTNUMBER: config.get(INI_KMS_SECTION, KMIP_PORTNUMBER)
        }

        # For now prepending the XYZ.1. strings so these dicts can be used directly in attributes PATCH requests to iDRAC

        self.sekmcert_attributes = {
            f'SEKMCert.1.{SEKMCERT_COMMONNAME}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_COMMONNAME),
            f'SEKMCert.1.{SEKMCERT_COUNTRYCODE}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_COUNTRYCODE),
            f'SEKMCert.1.{SEKMCERT_EMAILADDRESS}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_EMAILADDRESS),
            f'SEKMCert.1.{SEKMCERT_LOCALITYNAME}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_LOCALITYNAME),
            f'SEKMCert.1.{SEKMCERT_ORGANIZATIONNAME}': config.get(INI_IDRAC_SEKMCERT_SECTION,
                                                                  SEKMCERT_ORGANIZATIONNAME),
            f'SEKMCert.1.{SEKMCERT_ORGANIZATIONUNIT}': config.get(INI_IDRAC_SEKMCERT_SECTION,
                                                                  SEKMCERT_ORGANIZATIONUNIT),
            f'SEKMCert.1.{SEKMCERT_STATENAME}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_STATENAME),
            f'SEKMCert.1.{SEKMCERT_SUBJECTALTNAME}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_SUBJECTALTNAME),
            f'SEKMCert.1.{SEKMCERT_USERID}': config.get(INI_IDRAC_SEKMCERT_SECTION, SEKMCERT_USERID)
        }

        self.kms_attributes = {
            f'KMS.1.{KMS_IDRACUSERNAME}': config.get(INI_IDRAC_KMS_SECTION, KMS_IDRACUSERNAME),
            f'KMS.1.{KMS_IDRACPASSWORD}': config.get(INI_IDRAC_KMS_SECTION, KMS_IDRACPASSWORD),
            f'KMS.1.{KMS_KMIPPORTNUMBER}': config.get(INI_IDRAC_KMS_SECTION, KMS_KMIPPORTNUMBER),
            f'KMS.1.{KMS_PRIMARYSERVERADDRESS}': config.get(INI_IDRAC_KMS_SECTION, KMS_PRIMARYSERVERADDRESS),
            f'KMS.1.{KMS_REDUNDANTKMIPPORTNUMBER}': config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTKMIPPORTNUMBER),
            f'KMS.1.{KMS_TIMEOUT}': config.get(INI_IDRAC_KMS_SECTION, KMS_TIMEOUT)}

        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS1):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS1}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS1)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS2):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS2}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS2)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS3):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS3}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS3)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS4):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS4}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS4)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS5):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS5}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS5)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS6):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS6}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS6)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS7):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS7}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS7)})
        if config.get(INI_IDRAC_KMS_SECTION, KMS_REDUNDANTSERVERADDRESS8):
            self.kms_attributes.update({f'KMS.1.{KMS_REDUNDANTSERVERADDRESS8}': config.get(INI_IDRAC_KMS_SECTION,
                                                                                           KMS_REDUNDANTSERVERADDRESS8)})
        self.sekm_attributes = {
            f'SEKM.1.{SEKM_IPADDRESSINCERTIFICATE}': config.get(INI_IDRAC_SEKM_SECTION, SEKM_IPADDRESSINCERTIFICATE),
            f'SEKM.1.{SEKM_KMSKEYPURGEPOLICY}': config.get(INI_IDRAC_SEKM_SECTION, SEKM_KMSKEYPURGEPOLICY)
        }

        self.controllers = config.get(INI_STORAGE_SECTION, STORAGE_SUPPORTED_CONTROLLERS).split(", ")

        if solution == 'perc':
            self.securitystatus_enabled = "SecurityKeyAssigned"
        elif solution == 'hba':
            self.securitystatus_enabled = ENABLED
        else:
            self.securitystatus_enabled = None


parser = argparse.ArgumentParser(
    description="Python script to enable SEKM and iLKM Solutions")
parser.add_argument('-ip', help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password', required=False)
parser.add_argument('-c', help='Pass in the name of the config.ini file which contains the iDRAC configuration.',
                    required=False)
parser.add_argument('-g', '--generate-template-ini', dest='generate_ini', action='store_true',
                    help='Only generate a template ini file and exit', required=False, default=False)
parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                    help='Increase log verbosity', required=False, default=False)
parser.add_argument('--enable-autosecure',
                    help='Use AutoSecure to automatically secure all capable physical disks when enabling solutions',
                    action='store_true', required=False)
parser.add_argument('--disable-autosecure',
                    help='Do not use AutoSecure to automatically secure all capable physical disks when enabling solutions',
                    action='store_true', required=False)
parser.add_argument('--ilkm', help='Enable the iLKM solution on the iDRAC device'
                                   'Cannot be used with --hba-sekm or --perc-sekm options'
                                   'Requires either --enable-autosecure or --disable-autosecure option'
                                   'Requires both --ilkm-key-id and --ilkm-key-passphrase options',
                    action='store_true', default=False, required=False)
parser.add_argument('--ilkm-key-id', help='The iLKM key id to use for enablement',
                    default=False, required=False)
parser.add_argument('--ilkm-key-passphrase', help='The iLKM passphrase to use for enablement',
                    default=False, required=False)
parser.add_argument('--hba-sekm', help='Enable the SEKM solution on an HBA devices'
                                       'Cannot be used with --ilkm or --perc-sekm options'
                                       'Requires either --enable-autosecure or --disable-autosecure option',
                    action='store_true', default=False, required=False)
parser.add_argument('--perc-sekm', help='Enable the SEKM solution on one or more PERC devices'
                                        'Cannot be used with --ilkm or --hba-sekm options',
                    action='store_true', default=False, required=False)

args = vars(parser.parse_args())

if args["generate_ini"]:
    generate_template_ini()
    sys.exit(0)

idrac_ip = args["ip"]
idrac_username = args["u"]
idrac_password = args["p"]
autosecure = None
solutions_args = {'ilkm': args.get('ilkm'), 'hba': args.get('hba_sekm'), 'perc': args.get('perc_sekm')}
autosecure_args = {'enable': args.get('enable_autosecure'), 'disable': args.get('disable_autosecure')}
ilkm_args = {'k': args.get('ilkm_key_id'), 'p': args.get('ilkm_key_passphrase')}

if not all([idrac_ip, idrac_username, idrac_password]) or not any(solutions_args.values()):
    parser.print_usage()
    sys.exit(1)
elif 1 != len([solution for solution in solutions_args.values() if solution]):
    print('Only one solution can be specified at a time')
    sys.exit(1)

solution = [arg for arg in solutions_args if solutions_args.get(arg)][0]

if 'perc' not in solution and (not any(autosecure_args.values() or all(autosecure_args.values()))):
    print(
        f'One of either --enable-autosecure or --disable-autosecure option is required for the {solution} solution option')
    sys.exit(1)
else:
    autosecure = any([True for arg in autosecure_args if arg == 'enable' and autosecure_args.get('enable')])

if solution == 'ilkm' and not all(ilkm_args.values()):
    print(f'You must specify both --ilkm-key-id and --ilkm-key-passphrase options for the {solution} solution')
    sys.exit(1)
elif solution != 'ilkm' and not args.get('c'):
    print(f'You must specify a config ini with -c option to use the {solution} solution')
    sys.exit(1)

if __name__ == "__main__":

    if solution in ('perc', 'hba'):
        config = SolutionScriptConfig()
        idrac = IdracFacade(config)
        thales_server = ThalesServerFacade(config)
        # configure key user and certificates
        kms_user_data = thales_server.create_and_get_user_info(
            config.sekmcert_attributes.get(f'SEKMCert.1.{SEKMCERT_COMMONNAME}'))
        thales_server.add_user_to_key_user_group(kms_user_data)
        idrac.set_sekmcert_attributes()
        unsigned_cert = idrac.generate_csr()
        ca_cert_path = thales_server.get_ca_cert()
        sleep(10)
        signed_cert_path = thales_server.get_signed_cert(unsigned_cert)
        idrac.import_certificate(KMS_SERVER_CA, ca_cert_path)
        idrac.import_certificate(SEKM_SSL_CERT, signed_cert_path)

        # enable sekm on idrac and raid controller
        idrac.set_kms_attributes()
        idrac.set_sekm_attributes()
        idrac.enable_idrac_sekm()
    else:
        idrac = IdracFacade()  # no config file required for ilkm

    if autosecure:
        idrac.set_idrac_autosecure(ENABLED)
    elif autosecure is False:
        idrac.set_idrac_autosecure(DISABLED)

    if solution != 'ilkm':
        _ = idrac.enable_controller_sekm_and_get_job_id()
    elif solution == 'ilkm':
        idrac.enable_idrac_ilkm(args.get('ilkm_key_id'), args.get('ilkm_key_passphrase'))
