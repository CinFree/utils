# -*- coding:utf-8 -*-

import base64
import hmac
import time
from hashlib import sha256
from urllib.parse import urlencode, unquote
from random import randint
import requests

# 配置信息
# 二级域名
SUN_DOMAIN = "www"
# 主域名
DOMAIN = "xxxxxx.com"
SECRETEID = "asdbadasda"
SECRETEKEY = "asdadada"


public_data = {
    "domain": DOMAIN,
    "Nonce": "%06d" % randint(0, 999999),
    "SecretId": SECRETEID,
    "SignatureMethod": "HmacSHA256",
}

head_url = "https://"
base_url = "cns.api.qcloud.com"
server_path = "/v2/index.php?"


def domain_ddns(ip, dm,):

    timestamp = int(time.time())
    post_data = {
        # 接口请求参数
        "Timestamp": timestamp,
        "Action": "RecordModify",
        "recordId": dm["id"],
        "subDomain": dm["name"],
        "recordType": "A",
        "recordLine": "默认",
        "value": ip,
    }
    post_data.update(public_data)
    print(post_data)
    # 获取原文字符串 并且排序
    original = "POST" + base_url + server_path + unquote(
        urlencode([(k, post_data[k]) for k in sorted(post_data.keys())]))

    # hmac加密
    hmac_code = hmac.new(SECRETEKEY.encode(),
                         original.encode(), sha256).digest()
    # base64生成密钥
    Signature = base64.b64encode(hmac_code).decode()
    # 把密钥加入请求参数
    post_data.update({"Signature": Signature})
    # 拼接请求地址
    url1 = head_url + base_url + server_path
    # 发起请求
    r = requests.post(url1, data=post_data)

    try:
        if r.json()["code"] == 0:
            print(r.text)
            return True
        else:
            print(r.text)
            return False
    except Exception as e:
        print("修改出错：\n", e)

        return


def query_domain_source(domain):

    timestamp = int(time.time())
    params = {
        "Action": "RecordList",
        "Timestamp": timestamp,
    }
    params.update(public_data)
    original = "POST" + base_url + server_path + \
        unquote(urlencode([(k, params[k]) for k in sorted(params.keys())]))

    hmac_code = hmac.new(SECRETEKEY.encode(),
                         original.encode(), sha256).digest()
    Signature = base64.b64encode(hmac_code).decode()
    params.update({"Signature": Signature})

    url = head_url + base_url + server_path
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36"
    }
    r = requests.post(url, data=params, headers=headers)

    data = r.json()["data"]["records"]
    for item in data:
        if item["name"] == domain:
            print("域名信息", "**"*12)
            print("域名ID: ", item["id"])
            print("子域名: ", item["name"])
            print("解析地址: ", item["value"])
            print("解析类型: ", item["type"])
            print("更新时间: ", item["updated_on"])
            return item


if __name__ == "__main__":

    # 从网络获取本地ip地址
    host_ip = requests.get("https://httpbin.org/ip").json()["origin"]
    print("域名信息：", SUN_DOMAIN + "." + DOMAIN)
    print("本地IP地址：", host_ip)

    # 从腾讯云获取域名解析信息
    domain_source = query_domain_source(SUN_DOMAIN)

    # 对比两个ip，如果不一致，就要重新解析
    if host_ip != domain_source["value"]:
        # 解析ip
        isok = domain_ddns(ip=host_ip, dm=domain_source)
        if isok:
            print("修改成功：", host_ip)
    else:
        print("IP一致，不需要解析")
