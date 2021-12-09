#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from logging import getLogger
from service_sqlalchemy.core.shortcuts import safe_transaction
from service_authlib.core.server.common.models.user import OAuth2UserModel
from service_authlib.core.server.common.models.token import OAuth2TokenModel
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as BaseRefreshTokenGrant

logger = getLogger(__name__)


class RefreshTokenGrant(BaseRefreshTokenGrant):
    """ 刷新令牌模式

    doc: https://docs.authlib.org/en/stable/flask/2/grants.html#refresh-token-grant

    1. oauth2_client表中必须存在对应的client_id和client_secret
    2. oauth2_client表中的client_metadata字段字典值中grant_types列表值中必须存在refresh_token

    请求1: /token
    Content-Type: application/x-www-form-urlencoded

    grant_type:refresh_token
    client_id:ops
    client_secret:ops
    refresh_token:nMuyf2jYFJ0352EdFMhufs3p6PJRj7v6kNXoxy7eJT4ltrOp

    响应1:
    Content-Type: application/json

    {
        "token_type": "Bearer",
        "access_token": "2HVieZKDujHsqh1SnxGsd3OeXSvyxd6UsgEd67FE23",
        "expires_in": 864000,
        "refresh_token": "e7YjE9RhO5HGObFsYvuxAEMEqd5ww4x0ObOMr9kTalN8UdoI"
    }
    """
    GRANT_TYPE = 'refresh_token'
    INCLUDE_NEW_REFRESH_TOKEN = False
    # 1. 支持通过Basic Auth方式传递client_id和client_secret获取token
    # 2. 支持通过Post  x-www-form-urlencoded编码方式传递client_id和client_secret获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def authenticate_refresh_token(self, refresh_token: t.Text) -> t.Union[OAuth2TokenModel, None]:
        """ 查询刷新令牌模型对象

        @param refresh_token: 刷新令牌
        @return: t.Union[OAuth2TokenModel, None]
        """
        with safe_transaction(self.server.service.ORM, commit=False) as session:
            logger.debug(f'query oauth2 token with refresh_token={refresh_token}')
            instance = session.query(
                OAuth2TokenModel
            ).filter(
                OAuth2TokenModel.refresh_token == refresh_token
            ).first()
        if not instance:
            logger.warning(f'wrong refresh_token')
            return
        if instance.is_expired():
            logger.warning(f'refresh_token has been expired')
            return
        if instance.is_revoked():
            logger.warning(f'refresh_token has been revoked')
        return instance

    def authenticate_user(self, credential: OAuth2TokenModel) -> t.Union[OAuth2UserModel, None]:
        """ 刷新令牌对象模型用户

        @param credential: 令牌模型对象
        @return: t.Union[OAuth2UserModel, None]
        """
        with safe_transaction(self.server.service.ORM, commit=False) as session:
            logger.debug(f'query oauth2 token user with id={credential.user_id}')
            instance = session.query(
                OAuth2UserModel
            ).filter(
                OAuth2UserModel.id == credential.user_id
            ).first()
        return instance

    def revoke_old_credential(self, credential: OAuth2TokenModel) -> None:
        """ 撤销老的令牌模型对象

        @param credential: 令牌模型对象
        @return: None
        """
        with safe_transaction(self.server.service.ORM, commit=True) as session:
            logger.debug(f'revoke old token {credential.access_token}')
            credential.revoked = True
            session.add(credential)
