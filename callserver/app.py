from flask import Flask, redirect, url_for, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import requests
import jwt
from datetime import datetime, timedelta
from urllib.parse import urlencode
from cache import tc
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
with app.app_context():
    db.create_all()

# OAuth2 Configuration
OAUTH2_CLIENT_NAME = 'CallServer'
OAUTH2_CLIENT_ID = 'Mh6xZZgAZm9YLECO97A5o8oI'
OAUTH2_CLIENT_SECRET = '123456'
OAUTH2_CLIENT_URI = 'http://localhost:8000/'
OAUTH2_REDIRECT_URI = OAUTH2_CLIENT_URI +'callback'
OAUTH2_AUTHORIZE_URL = 'https://localhost:8443/oauth/authorize'  # 授权url
OAUTH2_TOKEN_URL = 'https://localhost:8443/oauth/token' # 获取访问token的url
OAUTH2_REVOKE_URL = 'https://localhost:8443/oauth/revoke' # 撤销访问token的url
OAUTH2_RESOURCER_URL = 'https://localhost:8443/api/me' # 资源url

# JWT配置
JWT_SECRET_KEY = 'your_jwt_secret_key'
JWT_ALGORITHM = 'HS256'

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 401
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'error': 'Invalid authorization header format'}), 401
        
        token = parts[1]
        
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=JWT_ALGORITHM)
            user_id = payload.get('user_id')
            if tc.get( str(user_id) ):
                return f(payload, *args, **kwargs)
            else:
                return jsonify({'error': 'Token not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

    return decorator

@app.route('/login')
def login():
    params = {
        'response_type': 'code',
        'client_id': OAUTH2_CLIENT_ID,
        'redirect_uri': OAUTH2_REDIRECT_URI,
        'scope': 'profile',
    }
    url = f'{OAUTH2_AUTHORIZE_URL}?{urlencode(params)}'
    return redirect(url)

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(payload):
    user_id = str(payload.get('user_id'))
    user = User.query.filter_by(id=user_id).first()
    if user:
        tc.delete( str(user.id) )
        return jsonify({"message": "logout success", "status": "success"})
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/')
def index():
    return render_template('index.html',appname=OAUTH2_CLIENT_NAME)

@app.route('/callback')
def callback():
    print(request.args)
    code = request.args.get('code')
    if not code:
        return 'Authorization failed.'

    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': OAUTH2_REDIRECT_URI,
        'client_id': OAUTH2_CLIENT_ID,
        'client_secret': OAUTH2_CLIENT_SECRET
    }
    print(token_data)

    response = requests.post(OAUTH2_TOKEN_URL, data=token_data,verify=False)
    print(response.text)
    token_json = response.json()

    OAUTH2_REVOKE_URL
   
    if 'access_token' in token_json:
        access_token = token_json['access_token']
        response = requests.get(OAUTH2_RESOURCER_URL, headers = {'Authorization': f'Bearer {access_token}'},verify=False)

        resource_json = response.json()
        print(token_json)
        username = resource_json['username']

        user = User.query.filter_by(name=username).first()
        if not user:
            user = User(name=username)
            db.session.add(user)
            db.session.commit()

        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=1)  # 设置过期时间为1小时
        }
        jwt_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        tc.set(
            str(user.id),
            jwt_token
        )
        return render_template('callback.html', token=jwt_token)
    else:
        return 'Failed to obtain access token.'

@app.route('/api/userinfo', methods=['GET'])
@token_required
def user_info(payload):
    user_id = str(payload.get('user_id'))
    user = User.query.filter_by(id=user_id).first()
    if user:
        return jsonify({"user_id": user.id, "name": user.name, "status": "success"})
    else:
        return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(port=8000, debug=True)





if __name__ == '__main__':
    app.run(port=8000, debug=True)