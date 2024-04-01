import os.path
import sys

from time import time
from Cryptodome.Hash import HMAC, SHA1
import requests
from struct import pack, unpack
import json
from base64 import b64decode

# from apscheduler.schedulers.background import BackgroundScheduler

two_factor_time_query_url = "https://api.steampowered.com/ITwoFactorService/QueryTime/v0001"


# 得到时间补偿量，否则不能产生正确的code
def get_time_offset():
    twofactor_querytime_response = requests.post(url=two_factor_time_query_url, params={'http_timeout': 10}).json()
    ts = int(time())
    return int(twofactor_querytime_response.get('response', {}).get('server_time', ts)) - ts


def hmac_sha1(secret, data):
    return HMAC.new(secret, data, SHA1).digest()


# 根据校准后的时间生成令牌
def generate_twofactor_code_for_time(shared_secret, aligned_time):
    hmac = hmac_sha1(b64decode(shared_secret),
                     pack('>Q', int(aligned_time) // 30))  # this will NOT stop working in 2038

    start = ord(hmac[19:20]) & 0xF
    codeint = unpack('>I', hmac[start:start + 4])[0] & 0x7fffffff

    charset = '23456789BCDFGHJKMNPQRTVWXY'
    code = ''

    for _ in range(5):
        codeint, i = divmod(codeint, len(charset))
        code += charset[i]
    return code


# 模拟生成验证码
def generator_code(steam_id, user_name):
    steam_id_path = fr'.\maFiles\{steam_id}.maFile'
    user_name_path = fr'.\maFiles\{user_name}.maFile'
    # 从文件中读入shared_secrets
    if steam_id and os.path.exists(steam_id_path):
        with open(steam_id_path) as fn:
            js = fn.read()
            dic = json.loads(js)
            shared_secret = dic.get('shared_secret')
    elif os.path.exists(user_name_path):
        with open(user_name_path) as fn:
            js = fn.read()
            dic = json.loads(js)
            shared_secret = dic.get('shared_secret')
    if shared_secret:
        aligned_time = int(time() + get_time_offset())  # 补偿后的时间
        two_factor_code = generate_twofactor_code_for_time(shared_secret, aligned_time)
        if len(two_factor_code) == 5:
            return True, two_factor_code
        else:
            return False
