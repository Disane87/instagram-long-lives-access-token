import os
import ssl
import requests
from OpenSSL import crypto

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

def start_flask_server(app, config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config.cert_file, config.key_file)
    app.run(port=5000, ssl_context=context)

def get_short_lived_access_token(client_id, client_secret, redirect_uri, code):
    url = "https://graph.facebook.com/v12.0/oauth/access_token"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
        'code': code
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"HTTP request error: {e}")
        return {"error": str(e)}
    except ValueError:
        print("Response content is not valid JSON")
        return {"error": "Invalid JSON response"}

def get_accounts(access_token):
    url = f"https://graph.facebook.com/v12.0/me/accounts?fields=instagram_business_account{{id,name,username,profile_picture_url}}&access_token={access_token}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"HTTP request error: {e}")
        return {"error": str(e)}
    except ValueError:
        print("Response content is not valid JSON")
        return {"error": "Invalid JSON response"}

def get_long_lived_access_token(client_id, client_secret, short_lived_token):
    url = "https://graph.facebook.com/v12.0/oauth/access_token"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'fb_exchange_token',
        'fb_exchange_token': short_lived_token
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"HTTP request error: {e}")
        return {"error": str(e)}
    except ValueError:
        print("Response content is not valid JSON")
        return {"error": "Invalid JSON response"}

def get_user_info(access_token):
    url = f"https://graph.facebook.com/v20.0/me?fields=id,name,picture&access_token={access_token}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"HTTP request error: {e}")
        return {"error": str(e)}
    except ValueError:
        print("Response content is not valid JSON")
        return {"error": "Invalid JSON response"}

def get_recent_posts(access_token, user_id):
    url = f"https://graph.facebook.com/v20.0/{user_id}/media?fields=caption,comments_count,like_count,media_url&access_token={access_token}&limit=6"
    response = requests.get(url)

    if response.status_code != 200:
        return {"error": response.json()}

    return response.json()

def upload_image(access_token, user_id, image_url, caption):
    create_container_url = f"https://graph.facebook.com/v18.0/{user_id}/media"
    publish_url = f"https://graph.facebook.com/v18.0/{user_id}/media_publish"
    params = {
        "access_token": access_token,
        "image_url": image_url,
        "caption": caption
    }
    response = requests.post(create_container_url, params=params)

    if response.status_code != 200:
        return {"error": response.text}

    container_id = response.json().get("id")

    if container_id:
        publish_response = requests.post(publish_url, params={
            "access_token": access_token,
            "creation_id": container_id
        })
        return publish_response.json()
    else:
        return {"error": response.json()}
