#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from logging import getLogger
from authlib.oauth2.rfc6749.grants import ResourceOwnerPasswordCredentialsGrant

from service_authlib.core.server.common.models.user import OAuth2UserModel

logger = getLogger(__name__)


class PasswordGrant(ResourceOwnerPasswordCredentialsGrant):
    """ 密码模式

    doc: https://docs.authlib.org/en/stable/flask/2/grants.html#resource-owner-password-credentials-grant

    1. oauth2_client表中必须存在对应的client_id和client_secret
    2. oauth2_client表中的client_metadata字段字典值中grant_types列表值中必须存在password

    请求1: /token
    Content-Type: application/x-www-form-urlencoded

    grant_type:password
    client_id:ops
    client_secret:ops
    username:admin
    password:admin

    响应1:
    Content-Type: application/json

    {
        "token_type": "Bearer",
        "access_token": "2HVieZKDujHsqh1SnxGsd3OeXSvyxd6UsgEd67FE23",
        "expires_in": 864000,
        "refresh_token": "e7YjE9RhO5HGObFsYvuxAEMEqd5ww4x0ObOMr9kTalN8UdoI"
    }
    """

    GRANT_TYPE = 'password'
    # 1. 支持通过Basic Auth方式传递client_id和client_secret获取token
    # 2. 支持通过Post  x-www-form-urlencoded编码方式传递client_id和client_secret获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def authenticate_user(self, username: t.Text, password: t.Text) -> t.Union[OAuth2UserModel, None]:
        """ 用户模型对象用户

        @param username: 账户
        @param password: 密码
        @return: t.Union[OAuth2UserModel, None]

        注意: 密码模式只是兼容老版本而存在,特殊场景需求请重写依赖注入dependencies中的Oauth2或OpenID的setup方式注入自己的逻辑
        """
        raise NotImplementedError()
