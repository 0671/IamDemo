
import os
from flask import Flask
from models import db,User
from oauth2 import config_oauth
from routes import bp
from cmds import register_commands
from flask_login import LoginManager

def create_app(config=None):
    app = Flask(__name__)
    # app.config.from_object('website.settings')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'your_secret_key_here'
    db.init_app(app)

    # 设置 Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)
    @login_manager.user_loader
    def load_user(user_id):
        # 从数据库加载用户
        return User.query.get(int(user_id))
    
    config_oauth(app)

    app.register_blueprint(bp, url_prefix='')

    register_commands(app)
            
    return app
    
if __name__ == '__main__':
    create_app().run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=8443, debug=True)