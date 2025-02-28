import pytest

from oauthlogin.providers import OAuthToken, OAuthUser
from tests.providers.microsoft import MicrosoftOAuthProvider


class DummyMicrosoftOAuthProvider(MicrosoftOAuthProvider):
    def generate_state(self) -> str:
        return "dummy_state"
    
    def generate_nonce(self) -> str:
        return "dummy_nonce"

    def get_oauth_token(self, code, request):
        return OAuthToken(access_token="gho_key")

    def get_oauth_user(self, oauth_token):
        return OAuthUser(
            id="99",
            username="userone",
            email="user@example.com",
        )


@pytest.mark.django_db
def test_microsoft_provider(client, monkeypatch, settings):
    settings.OAUTH_LOGIN_PROVIDERS = {
        "microsoft": {
            "class": "provider_tests.test_microsoft.DummyMicrosoftOAuthProvider",
            "kwargs": {
                "client_id": "test_id",
                "client_secret": "test_secret",
                "scope": "user",
            },
        }
    }

    # Login required for this view
    response = client.get("/")
    assert response.status_code == 302
    assert response.url == "/login/?next=/"

    # User clicks the login link (form submit)
    response = client.post("/oauth/microsoft/login/")
    assert response.status_code == 302
    assert (
        response.url
        == "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test_id&nonce=dummy_nonce&redirect_uri=http%3A%2F%2Ftestserver%2Foauth%2Fmicrosoft%2Fcallback%2F&response_type=code&scope=user&state=dummy_state" 
    )

    # Microsoft redirects to the callback url
    response = client.get("/oauth/microsoft/callback/?code=test_code&state=dummy_state")
    assert response.status_code == 302
    assert response.url == "/"

    # Now logged in
    response = client.get("/")
    assert response.status_code == 200
    assert b"Hello userone!\n" in response.content

    # Check the user and connection that was created
    user = response.context["user"]
    assert user.username == "userone"
    assert user.email == "user@example.com"
    connections = user.oauth_connections.all()
    assert len(connections) == 1
    assert connections[0].provider_key == "microsoft"
    assert connections[0].provider_user_id == "99"
    assert connections[0].access_token == "gho_key"
    assert connections[0].refresh_token == ""
    assert connections[0].access_token_expires_at == None
