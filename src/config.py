import os

class Config:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = "https://localhost:5000/auth"
        self.received_code = None
        self.short_lived_token_response = {}
        self.long_lived_token_response = {}
        self.instagram_accounts = []
        self.cert_file = 'cert.pem'
        self.key_file = 'key.pem'

    def cert_exists(self):
        return os.path.exists(self.cert_file) and os.path.exists(self.key_file)

    def get_auth_url(self):
        return (
            f"https://www.facebook.com/v12.0/dialog/oauth"
            f"?client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
            f"&scope=instagram_basic,instagram_content_publish,instagram_manage_comments,instagram_manage_insights,pages_show_list,pages_read_engagement,business_management"
            f"&response_type=code"
        )

    def fetch_tokens(self):
        from src.utils import get_short_lived_access_token, get_long_lived_access_token, get_accounts

        self.short_lived_token_response = get_short_lived_access_token(self.client_id, self.client_secret, self.redirect_uri, self.received_code)
        if 'access_token' not in self.short_lived_token_response:
            print("Error fetching short-lived token:", self.short_lived_token_response)
            return

        short_lived_token = self.short_lived_token_response['access_token']
        self.long_lived_token_response = get_long_lived_access_token(self.client_id, self.client_secret, short_lived_token)
        if 'access_token' not in self.long_lived_token_response:
            print("Error fetching long-lived token:", self.long_lived_token_response)
            return

        accounts = get_accounts(self.long_lived_token_response['access_token'])
        if 'error' in accounts:
            print("Error fetching accounts:", accounts)
            return

        for account in accounts['data']:
            instagram_account = account['instagram_business_account']
            self.instagram_accounts.append({
                'id': instagram_account['id'],
                'username': instagram_account['username']
            })
