from flask import Flask, render_template, redirect, url_for, session, request
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from authlib.integrations.flask_client import OAuth
import subprocess
import os
import logging
import requests
from dotenv import load_dotenv

logging.basicConfig(level = logging.DEBUG)

load_dotenv()

client_id = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
client_secret = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # 设置登录视图
oauth = OAuth(app)

# 获取 Google 的 OpenID Connect 配置
google_config = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()

google = oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=client_id,
    client_secret=client_secret,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile',
                   'token_endpoint_auth_method': 'client_secret_basic'},
)

class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google_login')
def google_login():
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login/authorized')
def authorized():
    try:
        token = google.authorize_access_token()
        app.logger.debug(f"Received token: {token}")
        
        claims_options = {
            'iss': {
                'values': ['https://accounts.google.com', 'accounts.google.com']
            }
        }
        userinfo = google.parse_id_token(token, claims_options=claims_options)
        app.logger.debug(f"Parsed user info: {userinfo}")
        
        email = userinfo['email']
        app.logger.info(f"User email: {email}")
        
        if email.endswith('@g.ecc.u-tokyo.ac.jp'):
            login_user(User(email))
            return redirect(url_for('index'))
        else:
            return '只允许 @g.ecc.u-tokyo.ac.jp 域名的邮箱登录'
    except Exception as e:
        app.logger.error(f"Error in authorized function: {str(e)}", exc_info=True)
        return str(e), 500

@socketio.on('execute_command')
@login_required
def handle_command(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        emit('command_output', result)
    except subprocess.CalledProcessError as e:
        emit('command_output', str(e))

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)