import datetime

import requests
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from oauthlogin.exceptions import OAuthError
from oauthlogin.providers import OAuthProvider, OAuthToken, OAuthUser

# This is the Google OAuth provider
class GoogleOAuthProvider(OAuthProvider):
    authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
    discovery_document_url = "https://accounts.google.com/.well-known/openid-configuration"

    google_token_url = "https://oauth2.googleapis.com/token"
    google_user_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    google_emails_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    redirect_uri = "http://127.0.0.1:8000/oauth/google/callback/" 

    def _get_token(self, request_data,redirect_uri=None):
        if redirect_uri:
            request_data['redirect_uri'] = redirect_uri
        request_data["grant_type"] = "authorization_code"

        response = requests.post(
            self.google_token_url,
            headers={
                "Accept": "application/json",
            },
            data=request_data,
        )

        response.raise_for_status()
        data = response.json()
      
        id_token = data.get("id_token",'')
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})  # Decode without verification
        nonce_in_id_token = decoded_token.get("nonce", "")
        oauth_token = OAuthToken(
            access_token=data["access_token"]
        )

        # Expiration and refresh tokens are optional in Google depending on the access_type (offline/online)
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

        return oauth_token, nonce_in_id_token

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

    def get_oauth_user(self, *, oauth_token):
        response = requests.get(
            self.google_user_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {oauth_token.access_token}",
            },
        )
        response.raise_for_status()
        data = response.json()
        user_id = data.get("sub",None)
        verified_primary_email=None
       
        if data.get('email_verified',False):
            verified_primary_email=data.get('email',None)

        if not verified_primary_email:      
            raise OAuthError(_("A verified primary email address is required on Google"))
     
        return OAuthUser(
            id=user_id,
            email=verified_primary_email,
            username=verified_primary_email, #username,
        )
