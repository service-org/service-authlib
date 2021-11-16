#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import sqlalchemy as sa
import sqlalchemy_utils as su

from .base import BaseModel


class OAuthUserModel(BaseModel, su.Timestamp):
    """ OAuth用户 """
    __tablename__ = 'oauth_user'
    __table_args__ = (
        # 字典配置必须放最底部
        {'comment': 'OAuth用户'},
    )
    id = sa.Column(sa.BigInteger, primary_key=True, comment='唯一主键')
    name = sa.Column(sa.String(32), nullable=False, index=True, comment='用户姓名')
    mail = sa.Column(sa.String(32), nullable=False, index=True, comment='用户邮箱')

    def get_user_id(self) -> int:
        """ 获取用户ID """
        return self.id
