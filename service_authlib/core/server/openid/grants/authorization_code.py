#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from logging import getLogger
from authlib.oauth2 import OAuth2Request
from service_sqlalchemy.core.shortcuts import safe_transaction
from service_authlib.core.server.common.models.user import OAuth2UserModel
from service_authlib.core.server.common.models.client import OAuth2ClientModel
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant as BaseAuthorizationCodeGrant
from service_authlib.core.server.common.models.authorization_code import OAuth2AuthorizationCodeModel

logger = getLogger(__name__)


class AuthorizationCodeGrant(BaseAuthorizationCodeGrant):
    """ 授权码模式

    doc: https://docs.authlib.org/en/stable/flask/2/grants.html#authorization-code-grant

    1. oauth2_client表中必须存在对应的client_id
    2. oauth2_client表中client_metadata字段字典中redirect_uris列表值中必须包含redirect_uri
    3. oauth2_client表client_metadata字段字典值中grant_types列表值必须包含authorization_code
    4. oauth2_client表client_metadata字段字典值中grant_types列表值中必须包含refresh_token
    5. oauth2_client表client_metadata字段字典值中response_types列表值中必须包含code
    6. 当前时间减去oauth2_authorization_code表中的auth_time必须小于默认300秒有效期

    请求1: /authorize?response_type=code&scope=openid%20profile&client_id=ops&state=ops&redirect_uri=https%3A%2F%2Fwww.baidu.com%2F&nonce=1639028548812
    响应1: https://www.baidu.com/#error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request&state=ops
    响应2: https://www.baidu.com/?code=YAZZgiRHoPJ7h7WhqiJFytgsYR3Oi6JYVpCNfrckSan5KqZ7&state=ops
    请求2: /token
    Content-Type: application/x-www-form-urlencoded

    grant_type:authorization_code
    client_id:ops
    client_secret:ops
    code:1TZNJvOnFF7c6Yoy4oGJZmRC88F4gE2WqzZ14fzRjWrVR3Tc
    state:ops
    redirect_uri:https://www.baidu.com/

    响应2:
    Content-Type: application/json

    {
        "token_type": "Bearer",
        "access_token": "mwIfEDTdG9mgBFXM9xcFrXgrOENjM0t737w9MPuyAa",
        "expires_in": 864000,
        "refresh_token": "zx789Os7M1X6BVr5X9vIVl33ELCqK3JgqmKwPM2l8xQaILYT",
        "scope": "openid",
        "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzeXMiLCJhdWQiOlsib3BzIl0sImlhdCI6MTYzOTAyOTkwNywiZXhwIjoxNjM5MDMzNTA3LCJhdXRoX3RpbWUiOjE2MzkwMjk4OTQsIm5vbmNlIjoiMTYzOTAyODU0ODgxMiIsImF0X2hhc2giOiJ5SnRJMkV2dndYMjBuOGg3N0ppZ2lRIiwic3ViIjoxLCJuYW1lIjoiYWRtaW4ifQ.kwfPbZ7wahxPLfQnsXZgrM-iWc8OiXlXMWq4UvN5cQk"
    }
    """
    RESPONSE_TYPES = {'code'}
    GRANT_TYPE = 'authorization_code'
    # 1. 支持通过Basic Auth方式传递client_id和client_secret获取token
    # 2. 支持通过Post  x-www-form-urlencoded编码方式传递client_id和client_secret获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def save_authorization_code(self, code: t.Text, request: OAuth2Request) -> OAuth2AuthorizationCodeModel:
        """ 创建授权码模型对象

        @param code: 授权码
        @param request: oauth2请求对象
        @return: OAuth2AuthorizationCodeModel
        """
        with safe_transaction(self.server.service.ORM, commit=True) as session:
            client = request.client
            nonce = request.data.get('nonce')
            data = {
                'code': code, 'client_id': client.client_id,
                'nonce': nonce, 'redirect_uri': request.redirect_uri,
                'scope': request.scope, 'user_id': request.user.id
            }
            logger.debug(f'create openid code with {data}')
            instance = OAuth2AuthorizationCodeModel(**data)
            session.add(instance)
        return instance

    def query_authorization_code(
            self, code: t.Text, client: OAuth2ClientModel
    ) -> t.Union[OAuth2AuthorizationCodeModel, None]:
        """ 查询授权码模型对象

        @param code: 授权码
        @param client: oauth2客户端对象
        @return: t.Union[OAuth2AuthorizationCodeModel, None]
        """
        client_id = client.client_id
        with safe_transaction(self.server.service.ORM, commit=False) as session:
            logger.debug(f'query openid code with client_id={client_id}, code={code}')
            instance = session.query(
                OAuth2AuthorizationCodeModel
            ).filter(
                OAuth2AuthorizationCodeModel.code == code,
                OAuth2AuthorizationCodeModel.client_id == client_id
            ).first()
        if not instance:
            logger.warning(f'wrong client_id or code')
            return
        if instance.is_expired():
            logger.warning(f'code has been expired')
            return
        return instance

    def delete_authorization_code(self, authorization_code: OAuth2AuthorizationCodeModel) -> None:
        """ 删除授权码模型对象

        @param authorization_code: 授权码模型对象
        @return: None
        """
        with safe_transaction(self.server.service.ORM, commit=True) as session:
            logger.debug(f'delete openid code {authorization_code.code}')
            session.delete(authorization_code)

    def authenticate_user(self, authorization_code: OAuth2AuthorizationCodeModel) -> t.Union[OAuth2UserModel, None]:
        """ 授权码模型对象用户

        @param authorization_code: 授权码模型对象
        @return: t.Union[OAuth2UserModel, None]
        """
        with safe_transaction(self.server.service.ORM, commit=False) as session:
            logger.debug(f'query oauth2 code user with id={authorization_code.user_id}')
            user = session.query(
                OAuth2UserModel
            ).filter(
                OAuth2UserModel.id == authorization_code.user_id
            ).first()
        return user
