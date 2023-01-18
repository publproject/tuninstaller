import os,json
from flask import *

app = Flask(__name__)

@app.route('/create-ssh', methods=['POST'])
def create_ssh():
    auth_token = request.headers.get('Authorization')
    with open('/etc/publproject/tuninstaller/auth-token.txt','r') as data:
        server_token = data.read()
        server_token = server_token.replace("\n", "")
    if auth_token == server_token:
        client_post = request.get_json()
        user = client_post['username']
        passwd = client_post['password']
        exp = client_post['expired']
        os.system('api-exec ssh ' + user + ' ' + passwd + ' ' + exp )
        return 'Success'
    else:
        return 'Failed'

@app.route('/create-vmess', methods=['POST'])
def create_vmess():
    auth_token = request.headers.get('Authorization')
    with open('/etc/publproject/tuninstaller/auth-token.txt','r') as data:
        server_token = data.read()
        server_token = server_token.replace("\n", "")
    if auth_token == server_token:
        client_post = request.get_json()
        user = client_post['username']
        uuid = client_post['uuid']
        exp = client_post['expired']
        os.system('api-exec vmess ' + user + ' ' + uuid + ' ' + exp )
        return 'Success'
    else:
        return 'Failed'


@app.route('/create-vless', methods=['POST'])
def create_vless():
    auth_token = request.headers.get('Authorization')
    with open('/etc/publproject/tuninstaller/auth-token.txt','r') as data:
        server_token = data.read()
        server_token = server_token.replace("\n", "")
    if auth_token == server_token:
        client_post = request.get_json()
        user = client_post['username']
        uuid = client_post['uuid']
        exp = client_post['expired']
        os.system('api-exec vless ' + user + ' ' + uuid + ' ' + exp )
        return 'Success'
    else:
        return 'Failed'

@app.route('/create-trojan', methods=['POST'])
def create_trojan():
    auth_token = request.headers.get('Authorization')
    with open('/etc/publproject/tuninstaller/auth-token.txt','r') as data:
        server_token = data.read()
        server_token = server_token.replace("\n", "")
    if auth_token == server_token:
        client_post = request.get_json()
        user = client_post['username']
        uuid = client_post['uuid']
        exp = client_post['expired']
        os.system('api-exec trojan ' + user + ' ' + uuid + ' ' + exp )
        return 'Success'
    else:
        return 'Failed'

if __name__ == "__main__": 
 app.run(host='0.0.0.0', port=8080)
