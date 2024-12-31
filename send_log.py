import os
import boto3
import hmac
import hashlib
import base64
import requests
import subprocess
from datetime import datetime, timedelta
from dotenv import load_dotenv
from warrant.aws_srp import AWSSRP
from requests_aws4auth import AWS4Auth

SYSLOG_PATH='/var/log/syslog'
TIMESTAMP_FILE = "/home/pi/timestamp.txt"
load_dotenv()  # take environment variables from .env.
aws_userPoolId = os.environ['AWS_USERPOOLID']
aws_identityPoolId = os.environ['AWS_IDPOOLID']
aws_region = os.environ['AWS_REGION']
aws_clientId = os.environ['AWS_CLIENTID']
aws_userName = os.environ['AWS_USERNAME']
aws_password = os.environ['AWS_PASSWORD']
aws_clientSecret = os.environ['AWS_CLIENTSECRET']
aws_endPointUrl = os.environ['AWS_ENDPOINTURL']

def calculate_secret_hash(client_id, client_secret, username):
    message = username + client_id
    dig = hmac.new(
        client_secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def get_cognito_credentials():
    idp = boto3.client('cognito-idp', region_name=aws_region)
    identity = boto3.client('cognito-identity', region_name=aws_region)
    response = idp.initiate_auth(
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': aws_userName,
            'PASSWORD': aws_password,
            'SECRET_HASH': calculate_secret_hash(aws_clientId, aws_clientSecret, aws_userName)
        },
        ClientId=aws_clientId
    )

    id_token = response['AuthenticationResult']['IdToken']

    logins = {f'cognito-idp.{aws_region}.amazonaws.com/{aws_userPoolId}': id_token}
    identity_response = identity.get_id(
        IdentityPoolId=aws_identityPoolId,
        Logins=logins
    )

    credentials = identity.get_credentials_for_identity(
        IdentityId=identity_response['IdentityId'],
        Logins=logins
    )

    return credentials['Credentials']


def write_last_time(time):
    with open(TIMESTAMP_FILE, "w") as f:
        f.write(str(time))

def read_last_time():
    try:
        with open(TIMESTAMP_FILE, "r") as f:
            time_str = f.readline().strip()
            if time_str:
                return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
    except (FileNotFoundError, ValueError):
        pass

    return datetime.strptime((datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')


def read_log():
    last_time = read_last_time()
    new_logs = []
    latest_time = last_time
    with open(SYSLOG_PATH, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
        for line in lines:
            date_part = line[:19].replace('T', ' ')
            log_time = datetime.strptime(date_part, '%Y-%m-%d %H:%M:%S')
            #log_time = datetime.strptime(line[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S')
            updated_line = date_part + line[19:]
            if log_time > last_time:
                new_logs.append(updated_line.strip())
                #new_logs.append(line.strip())
                if log_time > latest_time:
                    latest_time = log_time

    if new_logs:
        write_last_time(latest_time)
    return new_logs

def post_log(endpoint_url, logs):
    load_dotenv()
    region = os.environ['AWS_REGION']
    credentials = get_cognito_credentials()
    access_key_id = credentials['AccessKeyId']
    secret_key = credentials['SecretKey']
    session_token = credentials['SessionToken']
    output = subprocess.check_output("grep Serial /proc/cpuinfo | awk '{print substr($3,9,8)}'", shell=True)
    device_id = output.strip().decode('utf-8')

    auth = AWS4Auth(access_key_id, secret_key, region, 'execute-api', session_token=session_token)
    payload = {
        "device_id": device_id,
        "timestamp": datetime.now().isoformat(),
        "logs": logs
    }
    headers = {"Content-Type": "application/json"}
    try:
        responce = requests.post(endpoint_url, auth=auth, headers=headers, json=payload)
        responce.raise_for_status()
        print(responce.text)
    except requests.exceptions.RequestException as e:
        print("Log post error: ", e)
        print(responce.text)

if __name__ == '__main__':
    endpoint_url = aws_endPointUrl
    logs = read_log()
    print(logs)
    post_log(endpoint_url, logs)
