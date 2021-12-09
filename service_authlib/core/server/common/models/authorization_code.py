#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import sqlalchemy as sa
import sqlalchemy_utils as su

from sqlalchemy.orm import relationship
from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin

from .base import BaseModel


class OAuth2AuthorizationCodeModel(BaseModel, OAuth2AuthorizationCodeMixin, su.Timestamp):
    """ OAuth2授权码 """
    __tablename__ = 'oauth2_authorization_code'
    __table_args__ = (
        # 字典配置必须放最底部
        {'comment': 'OAuth2授权码'},
    )
    id = sa.Column(sa.BigInteger, primary_key=True, comment='唯一主键')
    user_id = sa.Column(sa.BigInteger, sa.ForeignKey('oauth2_user.id', ondelete='CASCADE'), comment='用户 ID')
    user = relationship('OAuth2UserModel', backref='authorization_codes')
