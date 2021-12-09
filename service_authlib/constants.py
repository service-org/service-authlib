#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

# Authlib配置
AUTHLIB_CONFIG_KEY = 'AUTHLIB'

# 默认Jwt配置
DEFAULT_OPENID_JWT_CONFIG = {
    # 加解密id_token密钥
    'key': 'service',
    # oidc-server url
    'iss': 'service',
    # 默认jwt的加密方式
    'alg': 'HS256',
    # 默认jwt的过期时间
    'exp': 864000
}
