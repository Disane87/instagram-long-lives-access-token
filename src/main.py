import argparse
import ssl
import threading
import time
import webbrowser
import os
from flask import Flask
from dotenv import load_dotenv
from src.config import Config
from src.routes import setup_routes
from src.utils import create_self_signed_cert, start_flask_server

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description='Get Instagram long-lived access token.')
    parser.add_argument('--client-id', type=int, default=os.getenv('CLIENT_ID'), help='Your Facebook app client ID')
    parser.add_argument('--client-secret', type=str, default=os.getenv('CLIENT_SECRET'), help='Your Facebook app client secret')
    
    args = parser.parse_args()
    print("Args: ", args)
    config = Config(args.client_id, args.client_secret)

    if not config.client_id or not config.client_secret or not config.redirect_uri:
        print("Error: Missing required parameters. Ensure they are set in the .env file or passed as arguments.")
        return

    if not config.cert_exists():
        create_self_signed_cert(config.cert_file, config.key_file)

    app = Flask(__name__, template_folder='../public', static_folder='../static')
    setup_routes(app, config)

    server_thread = threading.Thread(target=start_flask_server, args=(app, config))
    server_thread.daemon = True
    server_thread.start()

    auth_url = config.get_auth_url()
    webbrowser.open(auth_url)

    while not config.received_code:
        print("Waiting for the authorization code...")
        time.sleep(1)

    config.fetch_tokens()

    while True:
        time.sleep(10)

if __name__ == '__main__':
    main()
