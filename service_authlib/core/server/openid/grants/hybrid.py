#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from logging import getLogger
from authlib.oidc.core import UserInfo
from authlib.oauth2 import OAuth2Request
from authlib.oidc.core.grants import OpenIDHybridGrant
from service_sqlalchemy.core.shortcuts import safe_transaction
from service_authlib.constants import DEFAULT_OPENID_JWT_CONFIG
from service_authlib.core.server.common.models.user import OAuth2UserModel
from service_authlib.core.server.common.models.authorization_code import OAuth2AuthorizationCodeModel

logger = getLogger(__name__)


class HybridGrant(OpenIDHybridGrant):
    """ 混合模式

    doc: https://docs.authlib.org/en/latest/flask/2/openid-connect.html#hybrid-flow
    """

    GRANT_TYPE = 'code'
    DEFAULT_RESPONSE_MODE = 'fragment'
    RESPONSE_TYPES = {'code id_token', 'code token', 'code id_token token'}
    # 1. 支持只传递client_id获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['none']

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

    def exists_nonce(self, nonce: t.Text, request: OAuth2Request) -> bool:
        """ 检查nonce是否存在

        @param nonce: 随机码
        @param request: 请求对象
        @return: bool
        """
        with safe_transaction(self.server.service.ORM, commit=False) as session:
            instance = session.query(
                OAuth2AuthorizationCodeModel
            ).filter(
                OAuth2AuthorizationCodeModel.nonce == nonce
            ).first()
        return bool(instance)

    def get_jwt_config(self) -> t.Dict[t.Text, t.Any]:
        """ 获取默认的jwt配置

        @return: None
        """
        return DEFAULT_OPENID_JWT_CONFIG | self.server.config.get('jwt_config', {}) or {}

    def generate_user_info(self, user: OAuth2UserModel, scope: t.Text) -> t.Dict[t.Text, t.Any]:
        """ 生成用户信息

        @param user: 用户对象
        @param scope: 权限范围
        @return: t.Dict[t.Text, t.Any]
        """
        return UserInfo(sub=user.id, name=user.name)
