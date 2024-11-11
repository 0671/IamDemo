import time
from flask import Blueprint, request, session, url_for, flash
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from models import db, User, OAuth2Client, AccessPermission
from oauth2 import authorization, require_oauth
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from utils import admin_required

bp = Blueprint('main', __name__)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

# 首页
@bp.route('/')
@login_required
def index():
    return render_template('index.html')
# 登陆接口
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')
# 登出接口
@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.login'))
# 管理员页面
@bp.route('/admin_page')
@admin_required
def admin_page():
    users = User.query.all()
    clients = OAuth2Client.query.all()
    return render_template('admin_page.html', users=users, clients=clients)
# 管理接口：创建用户
@bp.route('/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        try:
            new_user = User(username=username, password=password,role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('main.admin_page'))
    return render_template('manage_user.html')
# 管理接口：删除用户
@bp.route('/delete_user', methods=['GET'])
@admin_required
def delete_user():
    if request.method == 'GET':
        user_id = request.args.get("id")
        user = User.query.filter_by(id=user_id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            flash(f"User {user_id} is deleted.", 'success')
        else:
            flash("User not found.", 'danger')
    return redirect(url_for('main.admin_page'))
# 管理接口：修改用户的权限
@bp.route('/modify_access', methods=['POST'])
@admin_required
def modify_access():
    username = request.form['username']
    access = request.form['access'] == 'allow'
    user = User.query.filter_by(username=username).first()
    if user:
        permission = AccessPermission.query.filter_by(user_id=user.id).first()
        if permission:
            permission.can_access = access
        else:
            permission = AccessPermission(user_id=user.id, application_name="ExampleApp", can_access=access)
            db.session.add(permission)
        db.session.commit()
        flash(f"Access for {username} modified.", 'success')
    else:
        flash("User not found.", 'danger')
    return redirect(url_for('main.admin_page'))
# 管理接口：创建 oauth2 client
@bp.route('/create_client', methods=['GET', 'POST'])
@admin_required
def create_client():
    user = current_user
    if request.method == 'POST':
        client_id = gen_salt(24)
        client_id_issued_at = int(time.time())
        form = request.form
        client_metadata = {
            "client_name": form["client_name"],
            "client_uri": form["client_uri"],
            "grant_types": split_by_crlf(form["grant_type"]),
            "redirect_uris": split_by_crlf(form["redirect_uri"]),
            "response_types": split_by_crlf(form["response_type"]),
            "scope": form["scope"],
            "token_endpoint_auth_method": form["token_endpoint_auth_method"]
        }
        try:
            print(client_metadata)
            client = OAuth2Client(
                client_id=client_id,
                client_id_issued_at=client_id_issued_at,
                user_id=user.id,
            )
            client.set_client_metadata(client_metadata)
            if form['token_endpoint_auth_method'] == 'none':
                client.client_secret = ''
            else:
                client.client_secret = gen_salt(48)
            db.session.add(client)
            db.session.commit()
            flash('Client created successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('main.admin_page'))
    return render_template('manage_client.html')
# 管理接口：删除 oauth2 client
@bp.route('/delete_client', methods=['GET'])
@admin_required
def delete_client():
    if request.method == 'GET':
        client_id = request.args.get("id")
        # client_id = request.form['id']
        oclient = OAuth2Client.query.filter_by(client_id=client_id).first()
        if oclient:
            db.session.delete(oclient)
            db.session.commit()
            flash(f"Client {client_id} is deleted.", 'success')
        else:
            flash("Client not found.", 'danger')
    return redirect(url_for('main.admin_page'))
# oauth2 认证接口
@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('main.index'))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)

# oauth2 获取token接口
@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()
# oauth2 撤销token接口
@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')

# oauth2 获取资源接口
@bp.route('/api/me')
@require_oauth('profile') # 范围
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)