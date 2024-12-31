import os
import json
import boto3
import urllib.request
import urllib.error
from datetime import datetime

BUCKET_NAME = os.environ['BUCKET_NAME']
WEBHOOK_URL = os.environ['WEBHOOK_URL']
S3 = boto3.resource('s3')

def make_data(device_id, timestamp):
    """
    先頭: 要約文, ログ送信時間(timestamp), device_id,
    一行毎:
    loglevel, process, facility, timestamp,
    message
    """
    send_data = {
        "blocks": [
            {
                "type": "rich_text",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "emoji",
                                "name": "rotating_light",
                                "unicode": "1f6a8"
                            },
                            {
                                "type": "text",
                                "text": "以下のログを検知しました.\n"
                            }
                        ]
                    },
                    {
                        "type": "rich_text_quote",
                        "elements": [
                            {
                                "type": "text",
                                "text": "デバイス名:",
                                "style": {
                                    "bold": True
                                }
                            },
                            {
                                "type": "text",
                                "text": f'{device_id}\n'
                            },
                            {
                                "type": "text",
                                "text": "ログ送信日時:",
                                "style": {
                                    "bold": True
                                }
                            },
                            {
                                "type": "text",
                                "text": timestamp.strftime("%m/%d/%Y, %H:%M:%S")
                            }
                        ]
                    }
                ]
            },
        ]
    }

    for i in UNUSUAL_LOGS:
        parts = i.split(None, 5)
        time = f'{parts[0]} {parts[1]}'
        facility = parts[3].split(".")[0]
        logLevel = parts[3].split(".")[1].split(':')[0]
        process = parts[4].rstrip(':')
        message = parts[5]

        section = {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Log Level:*\n{logLevel}"},
                {"type": "mrkdwn", "text": f"*Process:*\n{process}"},
                {"type": "mrkdwn", "text": f"*facility:*\n{facility}"},
                {"type": "mrkdwn", "text": f"*Timestamp:*\n{time}"},
                {"type": "mrkdwn", "text": f"*message:*\n{message}"}
            ]
        }
        divider = {"type": "divider"}
        send_data["blocks"].append(divider)
        send_data["blocks"].append(section)
        send_data["blocks"].append(divider)

    return send_data

def send_message_to_slack(device_id, timestamp):
    send_data = make_data(device_id, timestamp)
    request_url = WEBHOOK_URL
    send_text = json.dumps(send_data).encode('utf-8')

    try:
        request_post = urllib.request.Request(url=request_url, method="POST", data=send_text)
        with urllib.request.urlopen(request_post) as res:
            body = res.read().decode()
            print(body)
    except urllib.error.HTTPError as error:
        status_code = error.code
        print("エラーログなし %s\n URL: %s" % (status_code, request_url))
    except urllib.error.URLError as error:
        status_code = "HTTP通信の不可"
        print(status_code)

def parse(log, device_id):
    """
    ログを分解してする関数.
    emergency, alert, critical, error
    を検知したら, エラーログ専用配列に追加する.

    Args:
        log (string): ログ本文
        device_id (string): デバイス識別子(MACアドレス)

    Returns:
        json: ログの分解後
    """
    parts = log.split(None, 5)
    logLevel = parts[3].split(".")[1].split(':')[0]
    if logLevel in ['emerg', 'alert', 'crit', 'err']:
        UNUSUAL_LOGS.append(log)

    return json.dumps({
        "timestamp": f'{parts[0]} {parts[1]}',
        "hostname": parts[2],
        "component": parts[3].rstrip(':'),
        "process": parts[4].rstrip(':'),
        "message": parts[5]
    })

def lambda_handler(event, context):
    global UNUSUAL_LOGS
    UNUSUAL_LOGS = []

    try:
        # イベントの構造を確認
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        elif isinstance(event.get('body'), dict):
            body = event['body']
        else:
            body = event
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': json.dumps('Invalid JSON in request body')
        }

    logs = body['logs']
    device_id = body['device_id']
    timestamp = datetime.fromisoformat(body['timestamp'])
    file_key = f"logs/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/{device_id}_logs{timestamp.strftime('%Y%m%d_%H%M%S')}.jsonl"

    log_lines = '\n'.join(parse(log, device_id) for log in logs)
    print(log_lines)

    if UNUSUAL_LOGS:
        send_message_to_slack(device_id, timestamp)

    try:
        obj = S3.Object(BUCKET_NAME, file_key)
        obj.put(Body=log_lines)
        print(f"File uploaded successfully: {file_key}")
    except Exception as e:
        print(f"Error uploading file: {str(e)}")

    return {
        'statusCode': 200,
        'body': json.dumps(f'This is {device_id}. We accepted your logs')
    }
