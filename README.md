# 框架
2个系统：
- iam系统：位于当前目录下，提供用户管理、Oauth2服务的功能
- callserver系统：位于目录callserver下，该系统是一个Ouath2 client

# 证书生成
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
- -x509：创建自签名证书
- -newkey rsa:4096：生成一个新的RSA密钥，长度为4096位。
- -keyout key.pem：将私钥保存到key.pem文件中
- -out cert.pem：将证书保存到cert.pem文件中
- -days 365：证书有效期为1年
- -nodes：不加密私钥，即无需密码就可以使用私钥

# 运行
1. 运行iam系统，创建管理员用户
```bash
python -m venv myenv
myenv\Scripts\activate
pip install -r requirements.txt
flask init-db
flask create-admin admin 123456
python app.py
```
2. 登陆iam系统，创建Oauth client数据
- Client Name 取 callserver/app.py 的 OAUTH2_CLIENT_NAME
- Client URI 取 callserver/app.py 的 OAUTH2_CLIENT_URI
- Redirect URIs 取 callserver/app.py 的 OAUTH2_REDIRECT_URI

创建成功后，可查看 OAUTH2_CLIENT_ID、OAUTH2_CLIENT_SECRET，填入到 callserver/app.py 中

3. 运行callserver系统，并使用Oauth2获取到iam系统的资源
```bash
python -m venv myenv
myenv\Scripts\activate
cd callserver\
python app.py
```
