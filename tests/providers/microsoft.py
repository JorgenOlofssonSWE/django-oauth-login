import datetime
import jwt
import requests
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from oauthlogin.exceptions import OAuthError
from oauthlogin.providers import OAuthProvider, OAuthToken, OAuthUser

class MicrosoftOAuthProvider(OAuthProvider):
    # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    authorization_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    discovery_document_url = " https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" # We should use 'organizations' instead of 'common' if we want to restrict the login to organisations only (not personal accounts)

    microsoft_token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    redirect_uri="http://localhost:8000/oauth/microsoft/callback/"

    def _get_token(self, request_data,redirect_uri=None):
        if redirect_uri:
            request_data['redirect_uri'] = redirect_uri
        request_data["grant_type"] = "authorization_code"

        response = requests.post(
            self.microsoft_token_url,
            headers={
                "Accept": "application/json",
            },
            data=request_data,
        )

        response.raise_for_status()
        data = response.json()
      
        id_token = data.get("id_token",'')
        decoded_id_token = jwt.decode(id_token, options={"verify_signature": False})  # Decode without verification
       
        oauth_token = OAuthToken(
            access_token=data["access_token"]
        )

        # Expiration and refresh tokens are optional in Azure depending on the access_type (offline/online)
        if "expires_in" in data:
            oauth_token.access_token_expires_at = timezone.now() + datetime.timedelta(
                seconds=data["expires_in"]
            )

        if "refresh_token" in data:
            oauth_token.refresh_token = data["refresh_token"]

        if "refresh_token_expires_in" in data:
            oauth_token.refresh_token_expires_at = timezone.now() + datetime.timedelta(
                seconds=data["refresh_token_expires_in"]
            )

        return oauth_token, decoded_id_token

    def get_oauth_token(self, *, code, request):
        redirect_uri = self.redirect_uri
        return self._get_token(
            {
                "client_id": self.get_client_id(),
                "client_secret": self.get_client_secret(),
                "code": code,              
            },
            redirect_uri=redirect_uri


        )

    def refresh_oauth_token(self, *, oauth_token):
        return self._get_token(
            {
                "client_id": self.get_client_id(),
                "client_secret": self.get_client_secret(),
                "refresh_token": oauth_token.refresh_token,
                "grant_type": "refresh_token",
            }
        )

    def get_oauth_user(self, *, oauth_token,id_token):
        # Extract the user from the id_token, the Azure platform send the id_token first response
        
        user_id = id_token.get("sub",None)
        email=None

        if id_token.get('email',''):
            email=id_token.get('email',None)

        if not email or not user_id:      
            raise OAuthError(_("A email address is required on Azure"))

        return OAuthUser(
            id=user_id,
            email=email,
            username=email, #username,
        )
    

  