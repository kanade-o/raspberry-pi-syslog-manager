# raspberry-pi-syslog-manager
**Raspberry Pi × AWS: Secure syslog Management System.**

This repository implements a secure syslog management pipeline that collects logs from Raspberry Pi, authenticates using AWS Cognito, and processes them via AWS API Gateway, Lambda, and S3. Critical logs are sent to Slack for notifications.

## Features
- Secure Communication: AWS Cognito for short-term tokens instead of long-term access keys.
- Efficient Log Management: Collects logs via rsyslog and processes them every 5 minutes using crontab.
- Log Storage & Notifications:
  - Logs stored in S3 in JSON Lines format.
  - Critical logs (error and above) notified to Slack.

## System Architecture
```
Raspberry Pi (rsyslog) 
    --> Cognito Authentication 
    --> API Gateway 
    --> Lambda Function 
        --> Slack Notification (for critical logs)
        --> S3 Storage (all logs)
```
## Prerequisites
- Hardware: Raspberry Pi 4-B (OS Lite 64-bit)
- Software: Python 3.11, AWS CLI configured
- AWS Services: Cognito, S3, API Gateway, Lambda, and Slack webhook.

# Installation and Setup
[Qiita](https://qiita.com/kanade-o/items/ae70b1d9dbb504304fed)
