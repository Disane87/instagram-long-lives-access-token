import os
from flask import request, render_template, redirect, url_for
from src.utils import get_recent_posts, get_long_lived_access_token, upload_image, get_user_info

def setup_routes(app, config):
    @app.route('/auth')
    def auth():
        config.received_code = request.args.get('code')
        return render_template('auth.html')

    @app.route('/tokens', methods=['GET', 'POST'])
    def tokens():
        if request.method == 'POST':
            if 'image_url' in request.form and 'account_id' in request.form:
                image_url = request.form['image_url']
                caption = request.form.get('caption', '')
                account_id = request.form['account_id']

                response = upload_image(config.long_lived_token_response['access_token'], account_id, image_url, caption)
                if response.get('error'):
                    print(f"Error uploading image: {response['error']}")


        user = get_user_info(config.long_lived_token_response['access_token']);
        
        accounts = {}
        for account in config.instagram_accounts:
            media_data = get_recent_posts(config.long_lived_token_response['access_token'], account['id'])
            accounts[account['username']] = {
                'media':  media_data.get('data', []),
                'info': account
            }


        return render_template('tokens.html', accounts=accounts, 
                               short_lived_token_response=config.short_lived_token_response,
                               long_lived_token_response=config.long_lived_token_response,
                               code=config.received_code,
                               user=user)

    @app.route('/renew_tokens', methods=['POST'])
    def renew_tokens():
        config.long_lived_token_response = get_long_lived_access_token(config.long_lived_token_response['access_token'], config.client_secret)
        return redirect(url_for('tokens'))
