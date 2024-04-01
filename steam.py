import base64
import logging
import requests
import rsa
import secrets
from requests.exceptions import RequestException
from fake_useragent import UserAgent
from sda_code import generator_code
from steam_pb2 import (
    IAuthenticationGetPasswordRsaPublicKeyRequest,
    IAuthenticationGetPasswordRsaPublicKeyResponse,
    device_details,
    LoginRequest,
    LoginRespones,
    allowed_confirmations,
    PollAuthSessionStatus_Request,
    PollAuthSessionStatus_Response,
    UpdateAuthSessionWithSteamGuardCode
)
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class SteamAuth:
    def __init__(self, username, password, email, email_pwd):
        self.username = username
        self.password = password
        self.email = email
        self.email_pwd = email_pwd
        self.ua = UserAgent().chrome
        self.session_id = self.get_session_id()
        self.browser_id = self.get_browser_id()
        self.session = requests.session()
        self.session.verify = False
        self.headers = {
            'user-agent': self.ua
        }
        self.steam_id = None
        self.client_id = None
        self.request_id = None
        self.access_token = None
        self.refresh_token = None

    def get_session_id(self):
        bytes_length = 12
        session_id = secrets.token_hex(bytes_length)
        return str(session_id)

    def get_browser_id(self):
        min_value = 1
        max_value = 2 ** 63 - 1
        browser_id = secrets.randbelow(max_value) + min_value
        return str(browser_id)

    def generator_protobuf(self, message):
        return base64.b64encode(message.SerializeToString()).decode()

    '''
    根据用户名获取rsa密钥
    '''

    def get_rsa_public_key(self):
        origin = 'https://steamcommunity.com'
        message = IAuthenticationGetPasswordRsaPublicKeyRequest(
            account_name=self.username
        )
        protobuf = self.generator_protobuf(message)
        url = 'https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1'

        params = {
            "origin": origin,
            "input_protobuf_encoded": protobuf
        }

        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = self.session.get(url, params=params, headers=self.headers, timeout=3)
                # 解析响应信息
                response = IAuthenticationGetPasswordRsaPublicKeyResponse.FromString(response.content)
                return True, response  # 成功时返回True和响应内容
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : get_rsa_public_key ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    '''
    根据密钥加密信息
    '''

    def rsa_encrypt(self, pubkey_n, pubkey_e):
        # 将十六进制字符串转换为整数
        rsa_n = int(pubkey_n, 16)
        rsa_e = int(pubkey_e, 16)
        # 用n值和e值生成公钥
        key = rsa.PublicKey(rsa_n, rsa_e)
        # 用公钥把明文加密
        message = rsa.encrypt(self.password.encode(), key)
        message = base64.b64encode(message).decode()
        return message

    '''
    发送加密后的登陆信息
    '''

    def send_encode_request(self, encrypted_password, encryption_timestamp):
        url = f'https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1'
        device_msg = device_details(
            device_friendly_name=self.ua,
            platform_type=2,
        )
        message = LoginRequest(
            account_name=self.username,
            encrypted_password=encrypted_password,
            encryption_timestamp=encryption_timestamp,
            set_remember_login=1,
            set_persistence=1,
            website_id="Store",
            device_details=[device_msg],
            language=0
        )
        protobuf = self.generator_protobuf(message)
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = self.session.post(url, params=params, headers=self.headers, timeout=5)
                response = LoginRespones.FromString(response.content)
                self.steam_id = response.steamid
                self.client_id = response.client_id
                self.request_id = response.request_id
                return True, response
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : send_encode_request ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)


    '''
    验证验证码
    '''

    def auth_code(self, code):
        message = UpdateAuthSessionWithSteamGuardCode(
            client_id=self.client_id,
            steamId=self.steam_id,
            code=code,
            code_type=3,
        )
        protobuf = self.generator_protobuf(message)
        url = f'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1'
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.post(url, params=params, headers=self.headers)
                # if response.status_code != 200:
                #     return False, "网络状态返回错误"
                eresult = response.headers['X-eresult']  # 打印响应头部信息
                if eresult == '1':
                    return True
                else:
                    return False
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : send_encode_request ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)
            except Exception as e:
                return False, str(e)
    '''
    获取token
    '''

    def get_token(self):
        url = f'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1'
        message = PollAuthSessionStatus_Request(
            ClientID=self.client_id,
            request_id=self.request_id
        )
        protobuf = self.generator_protobuf(message)
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.post(url, params=params, headers=self.headers, timeout=3)
                response = PollAuthSessionStatus_Response.FromString(response.content)
                if response:
                    self.access_token = response.access_token
                    self.refresh_token = response.refresh_token
                    return True
                return False
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : get_rsa_public_key ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    def get_history_inventory(self):
        url = f'https://steamcommunity.com/profiles/{self.steam_id}/inventoryhistory/?appid%5B%5D=730'
        cookies = {
            'sessionid': str(self.session_id),
            'steamid': str(self.steam_id),
            'steamLoginSecure': f'{self.steam_id}%7C%7C{self.access_token}',
            'steamRefresh_steam': f'{self.steam_id}%7C%7C{self.refresh_token}',
            'browserid': str(self.browser_id),
            'timezoneOffset': '28800,0',
            'steamCountry': 'CN%7C65c6e647746973917498bae6bced5fb9'
        }
        headers = {
            'user-agent': self.ua,
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.get(url, headers=headers, cookies=cookies, timeout=5)
                if response.status_code == 200:
                    return True, response.content
                elif response.status_code == 302:
                    return False, {"msg": "logout"}
                else:
                    return False, "网络状态返回错误"
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : get_rsa_public_key ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)


