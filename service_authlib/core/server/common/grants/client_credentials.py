#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant as BaseClientCredentialsGrant


class ClientCredentialsGrant(BaseClientCredentialsGrant):
    """ 客户端凭证模式

    doc: https://docs.authlib.org/en/stable/flask/2/grants.html#client-credentials-grant

    1. oauth2_client表中必须存在对应的client_id和client_secret
    2. oauth2_client表中client_metadata字段字典值中grant_types列表值中必须存在client_credentials

    请求1: /token
    Content-Type: application/x-www-form-urlencoded

    grant_type:client_credentials
    client_id:ops
    client_secret:ops

    响应1:
    Content-Type: application/json

    {
        "token_type": "Bearer",
        "access_token": "bKQ9HBy0ss5L7d7dV1MT0RXjXuGIz6RDsJ8aagVRVg",
        "expires_in": 864000
    }
    """
    GRANT_TYPE = 'client_credentials'
    # 1. 支持通过Basic Auth方式传递client_id和client_secret获取token
    # 2. 支持通过Post  x-www-form-urlencoded编码方式传递client_id和client_secret获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
