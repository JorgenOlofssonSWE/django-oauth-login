import datetime
import secrets
from typing import Any, List, Optional
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import login as auth_login
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import NoReverseMatch, reverse
from django.utils.crypto import get_random_string
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from .exceptions import (OAuthCannotDisconnectError, OAuthStateMismatchError, OAuthNonceMismatchError,
                        OAuthIDTokenValidationMismatchError, OAuthProviderNotConfiguredError)
from .models import OAuthConnection

SESSION_NEXT_KEY = "oauthlogin_next"
SESSION_NONCE_KEY = "oauthlogin_nonce"
SESSION_STATE_KEY = "oauthlogin_state"

class OAuthToken:
    def __init__(
        self,
        *,
        access_token: str,
        refresh_token: str = "",
        access_token_expires_at: Optional[datetime.datetime] = None,
        refresh_token_expires_at: Optional[datetime.datetime] = None,
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.access_token_expires_at = access_token_expires_at
        self.refresh_token_expires_at = refresh_token_expires_at


class OAuthUser:
    def __init__(self, *, id: str, email: str, username: str = ""):
        self.id = id
        self.username = username
        self.email = email

    def __str__(self):
        return self.email


class OAuthProvider:
    authorization_url = ""

    def __init__(
        self,
        *,
        # Provided automatically
        provider_key: str,
        # Required as kwargs in OAUTH_LOGIN_PROVIDERS setting
        client_id: str,
        client_secret: str,
        # Not necessarily required, but commonly used
        scope: str = "",
        tenant: str = "", # Azure tenant type or id, example: 'common' for Azure
        response_type: str = "",
        # Authentication backend only needs to be set if you have custom backends which don't include the default
        authentication_backend: str = "django.contrib.auth.backends.ModelBackend",
        # Fields for id_token validation
        aud: str = "", # Audience, example: 'api://<client_id>' for Azure
        tid: str = "", # Tenant ID, example: '<tenant_id>' for Azure
        iss: str = "", # Issuer, example: 'https://login.microsoftonline.com/<tenant_id>/v2.0' for Azure

    ):
        self.provider_key = provider_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.tenant = tenant
        self.response_type = response_type
        self.authentication_backend = authentication_backend
        self.aud = aud
        self.tid = tid
        self.iss = iss

    def get_authorization_url_params(self, *, request: HttpRequest) -> dict:
        self.response_type = "code" if self.response_type == "" else self.response_type
        return {
            "redirect_uri": self.get_callback_url(request=request),
            "client_id": self.get_client_id(),
            "scope": self.get_scope(),
            "state": self.generate_state(),
            "nonce": self.generate_nonce(),
            "response_type": self.response_type,
        }

    def refresh_oauth_token(self, *, oauth_token: OAuthToken) -> OAuthToken:
        raise NotImplementedError()

    def get_oauth_token(self, *, code: str, request: HttpRequest) -> OAuthToken:
        raise NotImplementedError()

    def get_oauth_user(self, *, oauth_token: OAuthToken) -> OAuthUser:
        raise NotImplementedError()

    def get_authorization_url(self, *, request: HttpRequest) -> str:
        return self.authorization_url

    def get_client_id(self) -> str:
        return self.client_id

    def get_client_secret(self) -> str:
        return self.client_secret

    def get_scope(self) -> str:
        return self.scope

    def get_callback_url(self, *, request: HttpRequest) -> str:
        url = reverse("oauthlogin:callback", kwargs={"provider": self.provider_key})
        return request.build_absolute_uri(url)

    def generate_state(self) -> str:
        return get_random_string(length=32)
    
    def generate_nonce(self) -> str:
        return get_random_string(length=24)

    def check_request_state(self, *, request: HttpRequest) -> None:
        state = request.GET.get("state", '')
        expected_state = request.session.pop(SESSION_STATE_KEY,'')
        if not secrets.compare_digest(state, expected_state):
            raise OAuthStateMismatchError()
      
    def check_id_token_nonce(self, *, returned_nonce:str, request: HttpRequest) -> None:
        expected_nonce = request.session.pop(SESSION_NONCE_KEY,'')
        if not secrets.compare_digest(returned_nonce, expected_nonce):
            raise OAuthNonceMismatchError()
    
    def validate_id_token(self, *, id_token:dict, request: HttpRequest) -> None:
        expected_aud = settings.OAUTH_LOGIN_PROVIDERS.get(self.provider_key, {}).get("kwargs", {}).get("aud", "")
        expected_tid = settings.OAUTH_LOGIN_PROVIDERS.get(self.provider_key, {}).get("kwargs", {}).get("tid", "")
        expected_iss = settings.OAUTH_LOGIN_PROVIDERS.get(self.provider_key, {}).get("kwargs", {}).get("iss", "")
        # Only try to validate if we have an expected value
        if expected_aud and not secrets.compare_digest(id_token.get("aud",""), expected_aud):
            raise OAuthIDTokenValidationMismatchError()
        if expected_tid and not secrets.compare_digest(id_token.get("tid",""), expected_tid):
            raise OAuthIDTokenValidationMismatchError()
        if expected_iss and not secrets.compare_digest(id_token.get("iss",""), expected_iss):
            raise OAuthIDTokenValidationMismatchError()

    def handle_login_request(self, *, request: HttpRequest) -> HttpResponse:
        authorization_url = self.get_authorization_url(request=request)
        authorization_params = self.get_authorization_url_params(request=request)
        
        if "state" in authorization_params:
            # Store the state in the session so we can check on callback
            request.session[SESSION_STATE_KEY] = authorization_params["state"]
        
        if "nonce" in authorization_params:
            # Store the nonce in the session so we can check on callback
            request.session[SESSION_NONCE_KEY] = authorization_params["nonce"]

        if "next" in request.POST:
            # Store in session so we can get it on the callback request
            request.session[SESSION_NEXT_KEY] = request.POST["next"]

        # Sort authorization params for consistency
        sorted_authorization_params = sorted(authorization_params.items())
        redirect_url = authorization_url + "?" + urlencode(sorted_authorization_params)
       
        return HttpResponseRedirect(redirect_url)

    def handle_connect_request(self, *, request: HttpRequest) -> HttpResponse:
        return self.handle_login_request(request=request)

    def handle_disconnect_request(self, *, request: HttpRequest) -> HttpResponse:
        provider_user_id = request.POST["provider_user_id"]
        connection = OAuthConnection.objects.get(
            provider_key=self.provider_key, provider_user_id=provider_user_id
        )
        if (
            request.user.has_usable_password()
            or request.user.oauth_connections.count() > 1
        ):
            connection.delete()
        else:
            raise OAuthCannotDisconnectError(
                _("Cannot remove last OAuth connection without a usable password")
            )

        redirect_url = self.get_disconnect_redirect_url(request=request)
        return HttpResponseRedirect(redirect_url)

    def handle_callback_request(self, *, request: HttpRequest) -> HttpResponse:
        self.check_request_state(request=request)

        result = self.get_oauth_token(code=request.GET.get("code",""), request=request)
        if isinstance(result, tuple) and len(result) == 2:
            # If we get a tuple back, it's (oauth_token, id_token_nonce)
            oauth_token, id_token = result
            self.check_id_token_nonce(returned_nonce=id_token.get("nonce",""), request=request)
            self.validate_id_token(id_token=id_token, request=request)
            oauth_user = self.get_oauth_user(oauth_token=oauth_token,id_token=id_token)
        else:
            oauth_token = result      
            oauth_user = self.get_oauth_user(oauth_token=oauth_token)
       
        if request.user.is_authenticated:
            connection = OAuthConnection.connect(
                user=request.user,
                provider_key=self.provider_key,
                oauth_token=oauth_token,
                oauth_user=oauth_user,
            )
            user = connection.user
        else:
            connection = OAuthConnection.get_or_createuser(
                provider_key=self.provider_key,
                oauth_token=oauth_token,
                oauth_user=oauth_user,
            )

            user = connection.user

            self.login(request=request, user=user)

        redirect_url = self.get_login_redirect_url(request=request)
        return HttpResponseRedirect(redirect_url)

    def login(self, *, request: HttpRequest, user: Any) -> HttpResponse:
        # Backend is *required* if there are multiple backends configured.
        # We could/should have our own backend, but that feels like an unnecessary addition right now?
        auth_login(request=request, user=user, backend=self.authentication_backend)

    def get_login_redirect_url(self, *, request: HttpRequest) -> str:
        try:
            # The LOGIN_REDIRECT_URL setting can be a named URL
            # which we need to reverse
            default_redirect_url = reverse(settings.LOGIN_REDIRECT_URL)
        except NoReverseMatch:
            default_redirect_url = settings.LOGIN_REDIRECT_URL

        return request.session.pop(SESSION_NEXT_KEY, default_redirect_url)

    def get_disconnect_redirect_url(self, *, request: HttpRequest) -> str:
        return request.POST.get("next", "/")


def get_oauth_provider_instance(*, provider_key: str) -> OAuthProvider:
    OAUTH_LOGIN_PROVIDERS = getattr(settings, "OAUTH_LOGIN_PROVIDERS", {})
    try:
        provider_class_path = OAUTH_LOGIN_PROVIDERS[provider_key]["class"]
        provider_class = import_string(provider_class_path)
        provider_kwargs = OAUTH_LOGIN_PROVIDERS[provider_key].get("kwargs", {})
    except KeyError:
        raise OAuthProviderNotConfiguredError()
    return provider_class(provider_key=provider_key, **provider_kwargs)


def get_provider_keys() -> List[str]:
    return list(getattr(settings, "OAUTH_LOGIN_PROVIDERS", {}).keys())

