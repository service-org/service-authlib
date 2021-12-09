#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from authlib.oidc.core import UserInfo
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749.grants import BaseGrant
from service_sqlalchemy.core.shortcuts import safe_transaction
from service_authlib.constants import DEFAULT_OPENID_JWT_CONFIG
from authlib.oidc.core.grants import OpenIDCode as BaseOpenIDCode
from service_authlib.core.server.common.models.user import OAuth2UserModel
from service_authlib.core.server.common.models.authorization_code import OAuth2AuthorizationCodeModel


class OpenIDCode(BaseOpenIDCode):
    """ OpenIDCode扩展

    doc: https://docs.authlib.org/en/latest/flask/2/openid-connect.html#code-flow
    """

    def __init__(self, require_nonce=False) -> None:
        """ 初始化实例

        @param require_nonce: 随机码必须?
        """
        self.grant = None
        super(OpenIDCode, self).__init__(require_nonce)

    def __call__(self, grant: BaseGrant) -> None:
        """ AS调用对象

        @param grant: 授权对象
        @return: None
        """
        self.grant = grant
        super(OpenIDCode, self).__call__(grant)

    def exists_nonce(self, nonce: t.Text, request: OAuth2Request) -> bool:
        """ 检查nonce是否存在

        @param nonce: 随机码
        @param request: 请求对象
        @return: bool
        """
        with safe_transaction(self.grant.server.service.ORM, commit=False) as session:
            instance = session.query(
                OAuth2AuthorizationCodeModel
            ).filter(
                OAuth2AuthorizationCodeModel.nonce == nonce
            ).first()
        return bool(instance)

    def get_jwt_config(self, grant: BaseGrant) -> t.Dict[t.Text, t.Any]:
        """ 获取默认的jwt配置

        @param grant: 授权对象
        @return: None
        """
        return DEFAULT_OPENID_JWT_CONFIG | grant.server.config.get('jwt_config', {}) or {}

    def generate_user_info(self, user: OAuth2UserModel, scope: t.Text) -> t.Dict[t.Text, t.Any]:
        """ 生成用户信息

        @param user: 用户对象
        @param scope: 权限范围
        @return: t.Dict[t.Text, t.Any]
        """
        return UserInfo(sub=user.id, name=user.name)
