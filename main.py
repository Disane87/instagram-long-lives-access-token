import requests
import argparse
from flask import Flask, request, render_template, redirect, url_for
import ssl
import threading
import webbrowser
import time
import os
from OpenSSL import crypto
from datetime import datetime, timedelta
from dotenv import load_dotenv

app = Flask(__name__, template_folder='public', static_folder='static')

client_id = ""
client_secret = ""
redirect_uri = ""
received_code = None

CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

short_lived_token_response = {}
long_lived_token_response = {}
user_id = ""
username = ""

def create_self_signed_cert(cert_file, key_file):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    cert = crypto.X509()
    cert.get_subject().C = "DE"
    cert.get_subject().ST = "NRW"
    cert.get_subject().L = "Viersen"
    cert.get_subject().O = "MyCompany"
    cert.get_subject().OU = "MyDivision"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
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
    return render_template('auth.html')

@app.route('/tokens', methods=['GET', 'POST'])
def tokens():
    global username, long_lived_token_response, user_id
    if request.method == 'POST':
        if 'image' in request.files:
            image = request.files['image']
            caption = request.form.get('caption', '')

            image_path = os.path.join('static', image.filename)
            image.save(image_path)

            create_container_url = f"https://graph.facebook.com/v18.0/{user_id}/media"
            publish_url = f"https://graph.facebook.com/v18.0/{user_id}/media_publish"
            params = {
                "access_token": long_lived_token_response['access_token'],
                "image_url": f"https://localhost:5000/static/{image.filename}",
                "caption": caption
            }
            response = requests.post(create_container_url, params=params)

            print(f"create_container_url: {create_container_url}, params {params}")

            if response.status_code != 200:
                print(f"Error creating container: {response.text}")
                return render_template('tokens.html', user_id=user_id, username=username,
                                       short_lived_token_response=short_lived_token_response,
                                       long_lived_token_response=long_lived_token_response)

            container_id = response.json().get("id")

            if container_id:
                publish_response = requests.post(publish_url, params={
                    "access_token": long_lived_token_response['access_token'],
                    "creation_id": container_id
                })
                publish_response_json = publish_response.json()
                if "id" in publish_response_json:
                    print(f"Image published successfully: {publish_response_json['id']}")
                else:
                    print(f"Error publishing image: {publish_response_json}")
            else:
                print(f"Error creating container: {response.json()}")

            return render_template('tokens.html', user_id=user_id, username=username,
                                   short_lived_token_response=short_lived_token_response,
                                   long_lived_token_response=long_lived_token_response)

    return render_template('tokens.html', user_id=user_id, username=username,
                           short_lived_token_response=short_lived_token_response,
                           long_lived_token_response=long_lived_token_response)

@app.route('/renew_tokens', methods=['POST'])
def renew_tokens():
    return redirect(url_for('main'))

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

def get_user_info(access_token):
    url = f"https://graph.instagram.com/me?fields=id,username&access_token={access_token}"
    response = requests.get(url)
    return response.json()

def start_flask_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    app.run(port=5000, ssl_context=context)

def main():
    global client_id, client_secret, redirect_uri, short_lived_token_response, long_lived_token_response, user_id, username
    
    load_dotenv()
    
    parser = argparse.ArgumentParser(description='Get Instagram long-lived access token.')
    parser.add_argument('--client_id', type=str, default=os.getenv('CLIENT_ID'), help='Your Facebook app client ID')
    parser.add_argument('--client_secret', type=str, default=os.getenv('CLIENT_SECRET'), help='Your Facebook app client secret')
    parser.add_argument('--redirect_uri', type=str, default=os.getenv('REDIRECT_URI'), help='Your redirect URI (should be https://localhost:5000/auth)')
    
    args = parser.parse_args()
    client_id = args.client_id
    client_secret = args.client_secret
    redirect_uri = args.redirect_uri

    if not client_id or not client_secret or not redirect_uri:
        print("Error: Missing required parameters. Ensure they are set in the .env file or passed as arguments.")
        return

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        create_self_signed_cert(CERT_FILE, KEY_FILE)

    server_thread = threading.Thread(target=start_flask_server)
    server_thread.daemon = True
    server_thread.start()

    auth_url = (
        f"https://api.instagram.com/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=user_profile,user_media"
        f"&response_type=code"
    )
    webbrowser.open(auth_url)

    while received_code is None:
        print("Waiting for the authorization code...")
        time.sleep(1)

    short_lived_token_response = get_short_lived_access_token(client_id, client_secret, redirect_uri, received_code)
    if 'access_token' not in short_lived_token_response:
        print("Error fetching short-lived token:", short_lived_token_response)
        return

    short_lived_token = short_lived_token_response['access_token']
    user_id = short_lived_token_response['user_id']
    print("Short-lived Token:", short_lived_token_response)

    long_lived_token_response = get_long_lived_access_token(short_lived_token, client_secret)
    if 'access_token' not in long_lived_token_response:
        print("Error fetching long-lived token:", long_lived_token_response)
        return

    long_lived_token = long_lived_token_response['access_token']
    expires_in = long_lived_token_response['expires_in']

    expiration_date = datetime.now() + timedelta(seconds=expires_in)
    expiration_date_str = expiration_date.strftime('%Y-%m-%d %H:%M:%S')

    long_lived_token_response['expires_at'] = expiration_date_str

    user_info = get_user_info(long_lived_token)
    username = user_info['username']

    print("Long-lived Token:", long_lived_token)
    print("Expires at:", expiration_date_str)
    print("Username:", username)
    print("User ID:", user_id)

    while True:
        time.sleep(10)

if __name__ == '__main__':
    main()
