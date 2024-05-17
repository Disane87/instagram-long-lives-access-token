import requests
import argparse
from flask import Flask, request
import ssl
import threading
import webbrowser
import time
import os
from OpenSSL import crypto

app = Flask(__name__)

client_id = ""
client_secret = ""
redirect_uri = ""
received_code = None

CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

def create_self_signed_cert(cert_file, key_file):
    # Create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "DE"
    cert.get_subject().ST = "NRW"
    cert.get_subject().L = "Viersen"
    cert.get_subject().O = "MyCompany"
    cert.get_subject().OU = "MyDivision"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    with open(cert_file, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(key_file, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))

@app.route('/auth')
def auth():
    global received_code
    received_code = request.args.get('code')
    return "Authorization code received. You can close this window."

def get_short_lived_access_token(client_id, client_secret, redirect_uri, code):
    url = "https://api.instagram.com/oauth/access_token"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
        'code': code
    }
    response = requests.post(url, data=payload)
    return response.json()

def get_long_lived_access_token(short_lived_token, client_secret):
    url = f"https://graph.instagram.com/access_token?grant_type=ig_exchange_token&client_secret={client_secret}&access_token={short_lived_token}"
    response = requests.get(url)
    return response.json()

def start_flask_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    app.run(port=5000, ssl_context=context)

def main():
    global client_id, client_secret, redirect_uri
    parser = argparse.ArgumentParser(description='Get Instagram long-lived access token.')
    parser.add_argument('client_id', type=str, help='Your Facebook app client ID')
    parser.add_argument('client_secret', type=str, help='Your Facebook app client secret')
    parser.add_argument('redirect_uri', type=str, help='Your redirect URI (should be https://localhost:5000/auth)')
    
    args = parser.parse_args()
    client_id = args.client_id
    client_secret = args.client_secret
    redirect_uri = args.redirect_uri

    # Create certs if they don't exist
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        create_self_signed_cert(CERT_FILE, KEY_FILE)

    # Start the Flask server in a separate thread
    server_thread = threading.Thread(target=start_flask_server)
    server_thread.daemon = True
    server_thread.start()

    # Open the web browser for user to authenticate
    auth_url = (
        f"https://api.instagram.com/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=user_profile,user_media"
        f"&response_type=code"
    )
    webbrowser.open(auth_url)

    # Wait for the authorization code
    while received_code is None:
        print("Waiting for the authorization code...")
        time.sleep(1)

    # Get short-lived access token
    short_lived_token_response = get_short_lived_access_token(client_id, client_secret, redirect_uri, received_code)
    if 'access_token' not in short_lived_token_response:
        print("Error fetching short-lived token:", short_lived_token_response)
        return

    short_lived_token = short_lived_token_response['access_token']
    print("Short-lived Token:", short_lived_token_response)

    # Exchange short-lied token for long-lived access token
    long_lived_token_response = get_long_lived_access_token(short_lived_token, client_secret)
    if 'access_token' not in long_lived_token_response:
        print("Error fetching long-lived token:", long_lived_token_response)
        return

    print("Long-lived Token:", long_lived_token_response)

if __name__ == '__main__':
    main()
