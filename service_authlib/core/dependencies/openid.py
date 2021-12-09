#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from service_authlib.constants import AUTHLIB_CONFIG_KEY
from service_core.core.service.dependency import Dependency
from service_authlib.core.server.common.models import OAuth2TokenModel
from service_authlib.core.server.common.models import OAuth2ClientModel
from service_authlib.core.server.common import OAuth2AuthorizationServer
from service_authlib.core.server.openid.grants.hybrid import HybridGrant
from service_authlib.core.server.common.grants.password import PasswordGrant
from service_authlib.core.server.openid.grants.implicit import ImplicitGrant
from service_authlib.core.server.openid.extend.openid_code import OpenIDCode
from service_authlib.core.server.common.grants.refresh_token import RefreshTokenGrant
from service_authlib.core.server.common.grants.client_credentials import ClientCredentialsGrant
from service_authlib.core.server.openid.grants.authorization_code import AuthorizationCodeGrant


class OpenID(Dependency):
    """ OpenID依赖类 """

    name = 'OpenID'

    def __init__(
            self,
            alias: t.Text,
            orm_attr: t.Optional[t.Text] = None,
            provider_options: t.Optional[t.Dict[t.Text, t.Any]] = None,
            **kwargs: t.Any
    ) -> None:
        """ 初始化实例

        @param alias: 配置别名
        @param orm_attr: orm属性
        @param connect_options: 连接配置
        @param kwargs: 其它配置
        """
        self.alias = alias
        self.server = None
        self.orm_attr = orm_attr or 'orm'
        self.provider_options = provider_options or {}
        super(OpenID, self).__init__(**kwargs)

    def setup(self) -> None:
        """ 生命周期 - 载入阶段

        @return: None
        """
        orm_attr = self.container.config.get(f'{AUTHLIB_CONFIG_KEY}.{self.alias}.openid.orm_attr', default='')
        setattr(self.container.service, 'ORM', getattr(self.container.service, orm_attr or self.orm_attr))
        provider_options = self.container.config.get(f'{AUTHLIB_CONFIG_KEY}.{self.alias}.openid.provider_options',
                                                     default={})
        # 防止YAML中声明值为None
        provider_options = (provider_options or {}) | self.provider_options
        # 创建个OpenID授权服务器
        self.server = OAuth2AuthorizationServer(
            self.container.service, token_model=OAuth2TokenModel, client_model=OAuth2ClientModel, **provider_options
        )
        self.server.register_grant(
            HybridGrant,
            extensions=None
        )
        # self.server.register_grant(
        #     PasswordGrant,
        #     extensions=None
        # )
        self.server.register_grant(
            ImplicitGrant,
            extensions=None
        )
        self.server.register_grant(
            RefreshTokenGrant,
            extensions=None
        )
        self.server.register_grant(
            ClientCredentialsGrant,
            extensions=None
        )
        self.server.register_grant(
            AuthorizationCodeGrant,
            extensions=[OpenIDCode(require_nonce=True)]
        )

    def get_instance(self) -> OAuth2AuthorizationServer:
        """ 获取注入对象

        @return: OpenIDAuthorizationServer
        """
        return self.server
