#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t
import sqlalchemy as sa
import sqlalchemy_utils as su

from sqlalchemy.orm import relationship
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin

from .base import BaseModel


class OAuth2ClientModel(BaseModel, OAuth2ClientMixin, su.Timestamp):
    """ OAuth2客户端 """
    __tablename__ = 'oauth2_client'
    __table_args__ = (
        # 字典配置必须放最底部
        {'comment': 'OAuth2客户端'},
    )
    id = sa.Column(sa.BigInteger, primary_key=True, comment='唯一主键')
    user_id = sa.Column(sa.BigInteger, sa.ForeignKey('oauth2_user.id', ondelete='CASCADE'), comment='用户 ID')
    user = relationship('OAuth2UserModel', backref='clients')

    @property
    def token_endpoint_auth_method(self) -> t.Union[t.Text, None]:
        """ 配置的获取token的方法

        @return: t.Union[t.Text, None]
        """
        return self.client_metadata.get('token_endpoint_auth_method', None)

    def check_token_endpoint_auth_method(self, method: t.Text) -> bool:
        """ 检查下获取token的方法

        @param method: 方法名
        @return: bool
        """
        # 如果本地或数据库中没有指定获取token的方法依然允许尝试授权中其它获取token的方法
        return True if self.token_endpoint_auth_method is None else self.token_endpoint_auth_method == method
