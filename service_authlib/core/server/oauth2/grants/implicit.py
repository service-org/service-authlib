#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

from authlib.oauth2.rfc6749.grants import ImplicitGrant as BaseImplicitGrant


class ImplicitGrant(BaseImplicitGrant):
    """ 简化模式

    doc: https://docs.authlib.org/en/stable/flask/2/grants.html#implicit-grant

    1. oauth2_client表中必须存在对应的client_id
    2. oauth2_client表中client_metadata字段字典值中的grant_types列表值中必须包含implicit
    3. oauth2_client表中client_metadata字段字典值中的response_types列表值必须包含token

    请求1: /authorize?response_type=token&client_id=ops&state=ops&redirect_uri=https%3A%2F%2Fwww.baidu.com%2F
    响应1: https://www.baidu.com/#error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request&state=ops
    响应1: https://www.baidu.com/#token_type=Bearer&access_token=6ulEnRWpuknEBDJpeYkFDHT3KXmcmREIUyuIOYnIiy&expires_in=3600&state=ops
    """
    GRANT_TYPE = 'implicit'
    RESPONSE_TYPES = {'token'}
    # 1. 支持只传递client_id获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['none']
