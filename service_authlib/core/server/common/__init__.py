#! -*- coding: utf-8 -*-
#
# author: forcemain@163.com

from __future__ import annotations

import typing as t

from http import HTTPStatus
from authlib.oauth2 import HttpRequest
from authlib.oauth2 import OAuth2Request
from service_core.core.service import Service
from authlib.oauth2 import AuthorizationServer
from authlib.oauth2.rfc6750 import BearerToken
from authlib.common.encoding import to_unicode
from authlib.common.encoding import json_dumps
from authlib.common.security import generate_token
from service_webserver.core.request import Request
from service_webserver.core.response import Response
from authlib.oauth2.rfc6749.grants.base import BaseGrant
from service_sqlalchemy.core.shortcuts import safe_transaction
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from service_core.core.as_loader import load_dot_path_colon_obj

from .models import OAuth2UserModel
from .models import OAuth2TokenModel
from .models import OAuth2ClientModel

# 泛型类型 - create_oauth_request
T = t.TypeVar('T')
# 响应内容
HttpResponse = t.Optional[t.Union[t.Iterable[bytes], bytes, t.Iterable[str], str]]
# 响应状态
HttpStatus = t.Optional[t.Union[int, str, HTTPStatus]]
# 字典头部
HTTPDictHeaders = t.Mapping[str, t.Union[str, int, t.Iterable[t.Union[str, int]]]]
# 元组头部
HTTPIterHeaders = t.Iterable[t.Tuple[str, t.Union[str, int]]]
# 响应头部
HttpHeaders = t.Optional[t.Union[HTTPDictHeaders, HTTPIterHeaders]]


class OAuth2AuthorizationServer(AuthorizationServer):
    """ OAuth2授权类

    doc: https://docs.authlib.org/en/latest/flask/2/authorization-server.html
    """
    metadata_class = AuthorizationServerMetadata

    def __init__(
            self,
            service: Service,
            token_model: t.Type[OAuth2TokenModel],
            client_model: t.Type[OAuth2ClientModel],
            **config: t.Any,
    ) -> None:
        """ 初始化实例

        @param service: 服务对象
        @param client_model: 客户端模型
        @param token_model: 令牌模型
        @param config: 其它配置项
        """
        self.config = config
        self.token_model = token_model
        self.client_model = client_model
        metadata = config.get('metadata', {})
        if metadata:
            metadata = self.metadata_class(metadata)
            metadata.validate()
        self.service = service
        token_generator = config.get(
            'generate_token', self.create_bearer_token_generator()
        )
        super(OAuth2AuthorizationServer, self).__init__(
            self.get_oauth2_client, self.save_oauth2_token,
            generate_token=token_generator, metadata=metadata
        )

    def get_oauth2_client(self, client_id: t.Text) -> OAuth2ClientModel:
        """ 获取客户端对象

        @param client_id: 客户端对象id
        @return: OAuth2ClientModel
        """
        with safe_transaction(self.service.orm, commit=False) as session:
            return session.query(
                self.client_model
            ).filter(
                self.client_model.client_id == client_id
            ).first()

    def save_oauth2_token(self, token: t.Dict[t.Text, t.Any], request: OAuth2Request) -> OAuth2TokenModel:
        """ 创建一个令牌对象

        @param token: 令牌字典
        @param request: 请求对象
        @return: OAuth2TokenModel
        """
        with safe_transaction(self.service.orm, commit=True) as session:
            client = request.client
            if request.user:
                user_id = request.user.id
            else:
                user_id = client.user_id
            token = self.token_model(
                client_id=client.client_id,
                user_id=user_id, **token
            )
            session.add(token)
        return token

    @staticmethod
    def create_request(request: Request, request_cls: t.Type[T], use_json: t.Optional[bool] = False) -> T:
        """ 封装成请求对象

        @param request: 原始请求对象
        @param request_cls: 目标请求类
        @param use_json: 是否使用json
        @return: T
        """
        body = None
        if isinstance(request, request_cls):
            return request
        if request.method == 'POST':
            body = request.json if use_json else request.form.to_dict()
        if request.query_string:
            url = f'{request.base_url}?{to_unicode(request.query_string)}'
        else:
            url = request.base_url
        return request_cls(request.method, url, body=body, headers=request.headers)

    def create_oauth2_request(self, request: Request) -> OAuth2Request:
        """ 封为OAuth2Request

        @param request: 原始请求对象
        @return: OAuth2Request
        """
        return self.create_request(request, OAuth2Request, use_json=False)

    def create_json_request(self, request: Request) -> HttpRequest:
        """ 封为HttpRequest

        @param request: 原始请求对象
        @return: HttpRequest
        """
        return self.create_request(request, HttpRequest, use_json=True)

    def handle_response(self, status: HTTPStatus, body: HttpResponse, headers: HttpHeaders) -> Response:
        """ 处理并构造响应对象

        @param status: 响应码
        @param body: 响应内容
        @param headers: 响应头
        @return: t.Tuple[HttpResponse, HTTPStatus, HttpHeaders]
        """
        body = json_dumps(body) if isinstance(body, dict) else body
        return Response(response=body, status=status, headers=dict(headers))

    @staticmethod
    def create_token_generator(
            conf: t.Union[t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text], t.Text],
            length: int = 42
    ) -> t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text]:
        """ 创建通用令牌生成器

        @param conf: 令牌生成器配置
        @param length: 通用令牌长度
        @return: t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text]
        """
        if callable(conf):
            return conf
        if isinstance(conf, str):
            return load_dot_path_colon_obj(conf)[-1]

        def token_generator(
                client: t.Optional[OAuth2ClientModel] = None,
                grant_type: t.Optional[t.Text] = None,
                user: t.Optional[OAuth2UserModel] = None,
                scope: t.Optional[t.Text] = None,
                expires_in: t.Optional[int] = None,
                include_refresh_token: t.Optional[bool] = True
        ) -> t.Text:
            """ 默认令牌生成器

            @param client: 客户端模型对象
            @param grant_type: 授权类型
            @param user: 用户模型对象
            @param scope: 授权范围
            @param expires_in: 过期时间
            @param include_refresh_token: 包含刷新令牌? 默认包含
            @return: t.Text
            """
            return generate_token(length)

        return token_generator

    def create_access_token_generator(
            self,
            conf: t.Union[t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text], t.Text],
            length: int = 42
    ) -> t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text]:
        """ 创建访问令牌生成器

        @param conf: 令牌生成器配置
        @param length: 访问令牌长度
        @return: t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text]
        """
        return self.create_token_generator(conf, length=length)

    def create_refresh_token_generator(
            self,
            conf: t.Union[t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text], t.Text],
            length: int = 42
    ) -> t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text]:
        """ 创建刷新令牌生成器

        @param conf: 令牌生成器配置
        @param length: 刷新令牌长度
        @return: t.Callable[[OAuth2ClientModel, t.Text, OAuth2UserModel, t.Text, int, bool], t.Text]
        """
        return self.create_token_generator(conf, length=length)

    @staticmethod
    def create_token_expires_in_generator(conf: t.Optional[t.Dict[t.Text, t.Any]] = None) -> t.Callable:
        """ 创建过期时间生成器

        {
            'authorization_code': 864000,
            'implicit': 3600,
            'password': 864000,
            'client_credentials': 864000
        }

        @param conf: 过期生成器配置
        @return: t.Callable
        """
        data = {} | BearerToken.GRANT_TYPES_EXPIRES_IN | (conf or {})

        def expires_in(client: OAuth2ClientModel, grant_type: t.Text) -> int:
            """ 获取过期时间

            @param client: 客户端模型对象
            @param grant_type: 授权类型
            @return: int
            """
            return data.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

        return expires_in

    def create_bearer_token_generator(self) -> BearerToken:
        """ 创建令牌生成器 """
        # 创建访问令牌生成器
        generator = self.config.get('access_token_generator', True)
        access_token_generator = self.create_access_token_generator(generator, length=42)
        # 创建刷新令牌生成器
        generator = self.config.get('refresh_token_generator', False)
        refresh_token_generator = self.create_refresh_token_generator(generator, length=48)
        # 创建过期时间生成器
        generator = self.config.get('token_expires_in_generator', BearerToken.GRANT_TYPES_EXPIRES_IN)
        token_expires_in_generator = self.create_token_expires_in_generator(generator)
        # 返回统一令牌生成器
        return BearerToken(
            access_token_generator=access_token_generator,
            refresh_token_generator=refresh_token_generator,
            expires_generator=token_expires_in_generator,
        )

    def get_consent_grant(self, request: OAuth2Request) -> BaseGrant:
        """ 获取同意后授权对象

        @param request: 目标请求对象
        @return: BaseGrant
        """
        grant = self.get_authorization_grant(request)
        grant.validate_consent_request()
        grant.prompt = None if not hasattr(grant, 'prompt') else grant.prompt
        return grant

    def validate_consent_request(self, request: Request, end_user: t.Optional[OAuth2UserModel] = None) -> BaseGrant:
        """ 验证是否合法请求

        @param request: 请求对象
        @param end_user: 当前用户
        @return: BaseGrant
        """
        request = self.create_oauth2_request(request)
        request.user = end_user
        return self.get_consent_grant(request)
