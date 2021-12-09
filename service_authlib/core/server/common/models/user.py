#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import sqlalchemy as sa
import sqlalchemy_utils as su

from .base import BaseModel


class OAuth2UserModel(BaseModel, su.Timestamp):
    """ OAuth2用户 """
    __tablename__ = 'oauth2_user'
    __table_args__ = (
        # 字典配置必须放最底部
        {'comment': 'OAuth2用户'},
    )
    id = sa.Column(sa.BigInteger, primary_key=True, comment='唯一主键')
    name = sa.Column(sa.String(64), nullable=False, unique=True, comment='用户名')
