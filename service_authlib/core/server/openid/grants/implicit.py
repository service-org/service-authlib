#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from authlib.oidc.core import UserInfo
from authlib.oauth2 import OAuth2Request
from authlib.oidc.core.grants import OpenIDImplicitGrant
from service_sqlalchemy.core.shortcuts import safe_transaction
from service_authlib.constants import DEFAULT_OPENID_JWT_CONFIG
from service_authlib.core.server.common.models.user import OAuth2UserModel
from service_authlib.core.server.common.models.authorization_code import OAuth2AuthorizationCodeModel


class ImplicitGrant(OpenIDImplicitGrant):
    """ 简化模式

    doc: https://docs.authlib.org/en/latest/flask/2/openid-connect.html#implicit-flow

    1. oauth2_client表中必须存在对应的client_id
    2. oauth2_client表中client_metadata字段字典值中grant_types列表值中必须包含implicit
    3. oauth2_client表中client_metadata字段字典值中response_types列表值中必须包含id_token token或id_token
    4. oauth2_client表中client_metadata字段字典值中scope必须至少包含openid

    注意1: 默认会检查url参数中scope的值,且必须包含openid并与oauth2_client表中client_metadata字典值中scope对比获取允许的scope
    注意2: 默认会检查url参数中nonce的值,且必须与oauth2_authorization_code中的nonce字段的值不一样,否则视为放大攻击

    请求1: /authorize?response_type=id_token%20token&scope=openid%20profile&client_id=ops&state=ops&redirect_uri=https%3A%2F%2Fwww.baidu.com%2F&nonce=1639028548812
    响应1: https://www.baidu.com/#error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request&state=ops
    响应2: https://www.baidu.com/#token_type=Bearer&access_token=jeVjmJbiVmUvYga5HbEILHbo7nhk5FIU1BVWhU2Po1&expires_in=3600&scope=openid&id_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzeXMiLCJhdWQiOlsib3BzIl0sImlhdCI6MTYzOTAyODYyMSwiZXhwIjoxNjM5MDMyMjIxLCJhdXRoX3RpbWUiOjE2MzkwMjg2MjEsIm5vbmNlIjoiMTYzOTAyODU0ODgxMiciLCJhdF9oYXNoIjoiUTBBSnl6TVZiVWNWc2FmY1FmXy1wQSIsInN1YiI6MSwibmFtZSI6ImFkbWluIn0.tN5IS8x-JoeVYpWZJQwibwCQVGbh79byfpF1aPJOUuk&state=ops
    """
    GRANT_TYPE = 'implicit'
    DEFAULT_RESPONSE_MODE = 'fragment'
    RESPONSE_TYPES = {'id_token token', 'id_token'}
    # 1. 支持只传递client_id获取token
    TOKEN_ENDPOINT_AUTH_METHODS = ['none']

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
