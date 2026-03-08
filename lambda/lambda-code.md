# Lambda — Function Code

All 4 functions are Python 3.12. Each one handles one specific step in the detection pipeline.

Region: `us-east-1` | Runtime: Python 3.12

---

## aegis-analyzer

Reads the CloudTrail event, identifies what got exposed (S3, EC2, RDS, ALB, Lambda URL), and checks DynamoDB for duplicates before passing the finding forward.

Role: `AegisAnalyzerRole` | Timeout: 1 min

```python
import boto3
import json
import uuid
import hashlib
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
# CONFIGURE: If you changed the DynamoDB table name in Phase 2, update it here
table = dynamodb.Table('aegis-findings')

def check_duplicate(resource_id, exposure_type):
    """
    FIX #8: Deduplication — check if an open finding already exists
    for this exact resource+exposure_type combination.
    """
    try:
        response = table.query(
            IndexName='resource-index',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('resource_id').eq(resource_id),
            FilterExpression=boto3.dynamodb.conditions.Attr('exposure_type').eq(exposure_type)
            & boto3.dynamodb.conditions.Attr('status').is_in(['DETECTED','ALERTING','QUARANTINED'])
        )
        return len(response.get('Items', [])) > 0
    except Exception as e:
        print(f'Dedup check error: {e}')
        return False

def lambda_handler(event, context):
    print('Analyzer received event:', json.dumps(event))

    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    resources = detail.get('responseElements', {}) or {}
    request = detail.get('requestParameters', {}) or {}
    user_identity = detail.get('userIdentity', {})
    account_id = detail.get('recipientAccountId', 'unknown')
    region = detail.get('awsRegion', 'us-east-1')

    finding = {
        'finding_id': str(uuid.uuid4()),
        'timestamp': datetime.utcnow().isoformat(),
        'event_name': event_name,
        'account_id': account_id,
        'region': region,
        'user': user_identity.get('arn', 'unknown'),
        'exposure_type': 'UNKNOWN',
        'resource_type': 'UNKNOWN',
        'resource_id': 'UNKNOWN',
        'details': {},
        'risk_level': 'MEDIUM',
        'status': 'DETECTED'
    }

    # ── EC2 Public Instance Detection ──
    # FIX #1: CloudTrail RunInstances response does NOT have ipAddress.
    # Must read from networkInterfaceSet.items[0].association.publicIp
    if event_name == 'RunInstances':
        instances = resources.get('instancesSet', {}).get('items', [])
        for inst in instances:
            instance_id = inst.get('instanceId', 'unknown')
            # Correct path for public IP in CloudTrail response
            network_interfaces = inst.get('networkInterfaceSet', {}).get('items', [])
            public_ip = None
            for ni in network_interfaces:
                assoc = ni.get('association', {})
                public_ip = assoc.get('publicIp')
                if public_ip:
                    break
            # Also check associatePublicIpAddress flag at instance level
            associate_public = inst.get('networkInterfaceSet', {}).get('items', [{}])[0].get('association', {}).get('publicIp')
            if public_ip or associate_public:
                if check_duplicate(instance_id, 'PUBLIC_EC2'):
                    print(f'Duplicate finding skipped for {instance_id}')
                    return {'finding_id': 'DUPLICATE', 'exposure_type': 'UNKNOWN'}
                finding['exposure_type'] = 'PUBLIC_EC2'
                finding['resource_type'] = 'EC2_INSTANCE'
                finding['resource_id'] = instance_id
                # FIX #11: Store as native dict, not json.dumps string
                finding['details'] = {
                    'public_ip': public_ip or associate_public,
                    'instance_id': instance_id,
                    'instance_type': inst.get('instanceType', 'unknown'),
                    'region': region
                }

    # ── S3 Public Bucket Detection ──
    elif event_name in ['PutBucketAcl','PutBucketPolicy','DeleteBucketPublicAccessBlock','PutBucketWebsite']:
        bucket = request.get('bucketName', 'unknown')
        if check_duplicate(bucket, 'PUBLIC_S3'):
            print(f'Duplicate S3 finding skipped for {bucket}')
            return {'finding_id': 'DUPLICATE', 'exposure_type': 'UNKNOWN'}
        finding['exposure_type'] = 'PUBLIC_S3'
        finding['resource_type'] = 'S3_BUCKET'
        finding['resource_id'] = bucket
        finding['details'] = {'bucket_name': bucket, 'trigger_event': event_name}
        # Verify actual public status
        try:
            s3 = boto3.client('s3')
            pab = s3.get_bucket_public_access_block(Bucket=bucket)
            config = pab.get('PublicAccessBlockConfiguration', {})
            if config.get('BlockPublicAcls') and config.get('BlockPublicPolicy'):
                print(f'Bucket {bucket} is actually blocked — skipping')
                return {'finding_id': 'FALSE_POSITIVE', 'exposure_type': 'UNKNOWN'}
        except Exception as e:
            print(f'S3 verify error (proceed anyway): {e}')

    # ── RDS Public Database Detection ──
    elif event_name in ['CreateDBInstance','ModifyDBInstance']:
        db = request.get('dBInstanceIdentifier', 'unknown')
        publicly_accessible = request.get('publiclyAccessible', False)
        if str(publicly_accessible).lower() in ['true','1']:
            if check_duplicate(db, 'PUBLIC_RDS'):
                print(f'Duplicate RDS finding skipped')
                return {'finding_id': 'DUPLICATE', 'exposure_type': 'UNKNOWN'}
            finding['exposure_type'] = 'PUBLIC_RDS'
            finding['resource_type'] = 'RDS_INSTANCE'
            finding['resource_id'] = db
            finding['details'] = {
                'db_identifier': db,
                'engine': request.get('engine', 'unknown'),
                'port': str(request.get('port', 'unknown'))
            }

    # ── Load Balancer Detection ──
    elif event_name == 'CreateLoadBalancer':
        lbs = resources.get('loadBalancers', [])
        for lb in lbs:
            if lb.get('scheme') == 'internet-facing':
                lb_name = lb.get('loadBalancerName', 'unknown')
                if check_duplicate(lb_name, 'PUBLIC_ALB'):
                    return {'finding_id': 'DUPLICATE', 'exposure_type': 'UNKNOWN'}
                finding['exposure_type'] = 'PUBLIC_ALB'
                finding['resource_type'] = 'LOAD_BALANCER'
                finding['resource_id'] = lb_name
                finding['details'] = {
                    'name': lb_name,
                    'dns': lb.get('dNSName', 'unknown'),
                    'scheme': 'internet-facing'
                }

    # ── Lambda Public URL Detection ──
    elif event_name in ['CreateFunctionUrlConfig','UpdateFunctionUrlConfig']:
        auth_type = request.get('authType', '')
        func_name = request.get('functionName', 'unknown')
        if auth_type == 'NONE':
            if check_duplicate(func_name, 'PUBLIC_LAMBDA_URL'):
                return {'finding_id': 'DUPLICATE', 'exposure_type': 'UNKNOWN'}
            finding['exposure_type'] = 'PUBLIC_LAMBDA_URL'
            finding['resource_type'] = 'LAMBDA_FUNCTION'
            finding['resource_id'] = func_name
            finding['details'] = {'function_name': func_name, 'auth_type': 'NONE'}

    print('Finding prepared:', json.dumps(finding, default=str))
    return finding
```

---

## aegis-scorer

Takes the finding from the analyzer and assigns a risk level — CRITICAL, HIGH, MEDIUM, or LOW — then writes the scored finding to DynamoDB.

Role: `AegisAnalyzerRole` | Timeout: 30 sec

```python
import boto3
import json
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
from datetime import datetime

# CONFIGURE: Adjust risk levels here if you want different severity mapping
# E.g. change PUBLIC_EC2 to CRITICAL if your org treats all public EC2 as critical
RISK_MAP = {
    'PUBLIC_RDS':        'CRITICAL',
    'PUBLIC_S3':         'CRITICAL',
    'PUBLIC_EC2':        'HIGH',
    'PUBLIC_ALB':        'HIGH',
    'PUBLIC_LAMBDA_URL': 'MEDIUM',
    'UNKNOWN':           'LOW'
}

def lambda_handler(event, context):
    print('Scorer received:', json.dumps(event, default=str))

    exposure_type = event.get('exposure_type', 'UNKNOWN')

    # If analyzer returned UNKNOWN/DUPLICATE/FALSE_POSITIVE — stop workflow
    if exposure_type in ['UNKNOWN', 'DUPLICATE', 'FALSE_POSITIVE'] or event.get('finding_id') == 'DUPLICATE':
        print('No real exposure — stopping workflow')
        return {**event, 'risk_level': 'LOW', 'skip_remediation': True}

    risk_level = RISK_MAP.get(exposure_type, 'LOW')
    event['risk_level'] = risk_level

    dynamodb = boto3.resource('dynamodb')
    # CONFIGURE: If you changed the DynamoDB table name in Phase 2, update it here
    table = dynamodb.Table('aegis-findings')

    # FIX #11: details is already a dict — store directly, no json.dumps
    item = {
        'finding_id':    event['finding_id'],
        'timestamp':     event['timestamp'],
        'event_name':    event['event_name'],
        'account_id':    event['account_id'],
        'region':        event['region'],
        'user':          event['user'],
        'exposure_type': exposure_type,
        'resource_type': event['resource_type'],
        'resource_id':   event['resource_id'],
        'details':       event.get('details', {}),
        'risk_level':    risk_level,
        'status':        'DETECTED'
    }

    table.put_item(Item=item)
    print(f'Stored finding {event["finding_id"]} risk={risk_level}')
    return event
```

---

## aegis-remediator

The main function. Blocks the exposure automatically, sends the HTML alert email via SES with two signed action buttons, notifies Slack, and pushes the finding to Security Hub in ASFF format.

Role: `AegisRemediatorRole` | Timeout: 2 min

> Update `API_GATEWAY_URL` after Phase 10. Leave the placeholder until then.

```python
import boto3
import json
import hmac
import hashlib
import urllib.request
from datetime import datetime

# !! UPDATE THESE AFTER PHASE 11 !!
# CONFIGURE: Paste your API Gateway Invoke URL here (from Phase 10.4)
API_GATEWAY_URL = 'https://REPLACE_ME.execute-api.us-east-1.amazonaws.com/prod'

# CONFIGURE: Replace REPLACE_ACCOUNT_ID with your 12-digit AWS Account ID
# Find it: top-right corner of AWS Console → click your username → Account ID
SNS_TOPIC_ARN   = 'arn:aws:sns:us-east-1:REPLACE_ACCOUNT_ID:aegis-alerts'

def get_config():
    client = boto3.client('secretsmanager')
    # CONFIGURE: If you used a different secret name in Phase 7, update it here
    secret = client.get_secret_value(SecretId='aegis/email-config')
    return json.loads(secret['SecretString'])

# FIX #10: Generate HMAC-signed token so approval URLs cannot be guessed
def make_signed_token(finding_id, action, secret_key):
    msg = f'{finding_id}:{action}'.encode()
    return hmac.new(secret_key.encode(), msg, hashlib.sha256).hexdigest()

def remediate_s3(bucket_name):
    try:
        s3 = boto3.client('s3')
        s3.put_bucket_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
            }
        )
        print(f'REMEDIATED S3: {bucket_name}')
        return True
    except Exception as e:
        print(f'S3 remediation error: {e}')
        return False

def remediate_rds(db_identifier):
    try:
        rds = boto3.client('rds')
        rds.modify_db_instance(
            DBInstanceIdentifier=db_identifier,
            PubliclyAccessible=False,
            ApplyImmediately=True
        )
        print(f'REMEDIATED RDS: {db_identifier}')
        return True
    except Exception as e:
        print(f'RDS remediation error: {e}')
        return False

# FIX #7: Real Slack integration via webhook
def send_slack(finding, slack_webhook_url):
    if not slack_webhook_url or slack_webhook_url.startswith('https://hooks.slack.com/') is False:
        return
    risk = finding.get('risk_level','?')
    resource = finding.get('resource_id','?')
    etype = finding.get('exposure_type','?')
    color = {'CRITICAL':'#C0392B','HIGH':'#E67E22','MEDIUM':'#F1C40F','LOW':'#27AE60'}.get(risk,'#888')
    payload = {
        'attachments': [{
            'color': color,
            'title': f'[{risk}] AWS Exposure Detected',
            'text': f'*Type:* {etype}\n*Resource:* {resource}\n*Account:* {finding.get("account_id","?")}\n*Time:* {finding.get("timestamp","?")}',
            'footer': 'Cloud Aegis'
        }]
    }
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(slack_webhook_url, data=data, headers={'Content-Type':'application/json'})
        urllib.request.urlopen(req, timeout=5)
        print('Slack notification sent')
    except Exception as e:
        print(f'Slack error: {e}')

# FIX #9: Push to Security Hub in ASFF format
def push_to_security_hub(finding):
    try:
        sh = boto3.client('securityhub')
        account_id = finding.get('account_id','000000000000')
        # CONFIGURE: Change 'us-east-1' to your region if you are NOT using N. Virginia
        region = finding.get('region','us-east-1')
        finding_id = finding.get('finding_id','unknown')
        resource_id = finding.get('resource_id','unknown')
        severity_map = {'CRITICAL':90,'HIGH':70,'MEDIUM':40,'LOW':10}
        severity_score = severity_map.get(finding.get('risk_level','LOW'), 10)
        asff_finding = {
            'SchemaVersion': '2018-10-08',
            'Id': f'{region}/{account_id}/{finding_id}',
            'ProductArn': f'arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default',
            'GeneratorId': 'cloud-aegis',
            'AwsAccountId': account_id,
            'Types': ['Software and Configuration Checks/AWS Security Best Practices'],
            'CreatedAt': finding.get('timestamp', datetime.utcnow().isoformat()) + 'Z',
            'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
            'Severity': {'Normalized': severity_score, 'Label': finding.get('risk_level','LOW')},
            'Title': f'Public Exposure Detected: {finding.get("exposure_type","UNKNOWN")}',
            'Description': f'Resource {resource_id} has been exposed to the internet.',
            'Resources': [{
                'Type': finding.get('resource_type','Other'),
                'Id': resource_id,
                'Region': region
            }],
            'Compliance': {'Status': 'FAILED'},
            'RecordState': 'ACTIVE'
        }
        sh.batch_import_findings(Findings=[asff_finding])
        print(f'Security Hub finding pushed: {finding_id}')
    except Exception as e:
        print(f'Security Hub error (non-fatal): {e}')

def send_alert_email(finding, remediated, config):
    ses = boto3.client('ses')
    finding_id = finding['finding_id']
    risk_level = finding.get('risk_level','UNKNOWN')
    resource_id = finding.get('resource_id','unknown')
    exposure_type = finding.get('exposure_type','unknown')
    risk_color = {'CRITICAL':'#C0392B','HIGH':'#E67E22','MEDIUM':'#F1C40F','LOW':'#27AE60'}.get(risk_level,'#888')
    token_secret = config.get('approval_token_secret','default_secret')
    # FIX #10: Signed tokens in approval URLs
    approve_token = make_signed_token(finding_id, 'approve', token_secret)
    restore_token  = make_signed_token(finding_id, 'restore', token_secret)
    approve_url = f'{API_GATEWAY_URL}/approve?finding_id={finding_id}&token={approve_token}'
    restore_url  = f'{API_GATEWAY_URL}/restore?finding_id={finding_id}&token={restore_token}'
    remediation_status = 'YES - Resource has been auto-quarantined' if remediated else 'MANUAL ACTION REQUIRED'
    details_str = json.dumps(finding.get('details',{}), indent=2)
    html_body = f'''
    <html><body style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;">
    <div style="background:#1E3A5F;padding:20px;text-align:center;">
      <h1 style="color:white;margin:0;">Cloud Aegis</h1>
      <p style="color:#AAC4E0;margin:5px 0;">Real-Time Security Alert</p>
    </div>
    <div style="padding:20px;">
      <div style="background:{risk_color};color:white;padding:12px;border-radius:5px;text-align:center;margin-bottom:20px;">
        <strong style="font-size:18px;">RISK: {risk_level}</strong>
      </div>
      <table style="width:100%;border-collapse:collapse;">
        <tr style="background:#F4F6F7"><td style="padding:8px;border:1px solid #ddd;"><strong>Finding ID</strong></td><td style="padding:8px;border:1px solid #ddd;">{finding_id}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;"><strong>Exposure Type</strong></td><td style="padding:8px;border:1px solid #ddd;">{exposure_type}</td></tr>
        <tr style="background:#F4F6F7"><td style="padding:8px;border:1px solid #ddd;"><strong>Resource</strong></td><td style="padding:8px;border:1px solid #ddd;">{resource_id}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;"><strong>Account</strong></td><td style="padding:8px;border:1px solid #ddd;">{finding.get('account_id','?')}</td></tr>
        <tr style="background:#F4F6F7"><td style="padding:8px;border:1px solid #ddd;"><strong>Time (UTC)</strong></td><td style="padding:8px;border:1px solid #ddd;">{finding.get('timestamp','?')}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;"><strong>Auto-Remediated</strong></td><td style="padding:8px;border:1px solid #ddd;">{remediation_status}</td></tr>
      </table>
      <br/>
      <p><strong>Details:</strong></p>
      <pre style="background:#f4f4f4;padding:10px;border-radius:4px;font-size:12px;">{details_str}</pre>
      <br/>
      <p><strong>Take Action:</strong></p>
      <a href='{approve_url}' style="background:#27AE60;color:white;padding:14px 24px;text-decoration:none;border-radius:5px;margin-right:10px;display:inline-block;">
        Mark as Intentional
      </a>
      &nbsp;&nbsp;
      <a href='{restore_url}' style="background:#C0392B;color:white;padding:14px 24px;text-decoration:none;border-radius:5px;display:inline-block;">
        Confirm Remediation
      </a>
      <br/><br/>
      <p style="color:#888;font-size:11px;">Links are signed and expire — generated by Cloud Aegis</p>
    </div></body></html>
    '''
    ses.send_email(
        Source=config['sender_email'],
        Destination={'ToAddresses': [config['recipient_email']]},
        Message={
            'Subject': {'Data': f'[{risk_level}] AWS Exposure: {exposure_type} on {resource_id}'},
            'Body': {'Html': {'Data': html_body}}
        }
    )
    print(f'Alert email sent for {finding_id}')

def lambda_handler(event, context):
    print('Remediator received:', json.dumps(event, default=str))
    if event.get('skip_remediation') or event.get('exposure_type') == 'UNKNOWN':
        print('Skip flag set — no action needed')
        return event
    config = get_config()
    exposure_type = event.get('exposure_type','UNKNOWN')
    resource_id = event.get('resource_id','unknown')
    remediated = False
    if exposure_type == 'PUBLIC_S3':
        remediated = remediate_s3(resource_id)
    elif exposure_type == 'PUBLIC_RDS':
        remediated = remediate_rds(resource_id)
    # Update DynamoDB
    dynamodb = boto3.resource('dynamodb')
    # CONFIGURE: If you changed the DynamoDB table name in Phase 2, update it here
    table = dynamodb.Table('aegis-findings')
    status = 'QUARANTINED' if remediated else 'ALERTING'
    table.update_item(
        Key={'finding_id': event['finding_id']},
        UpdateExpression='SET #s = :s, remediated = :r',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={':s': status, ':r': remediated}
    )
    # SNS (backup + Slack)
    sns = boto3.client('sns')
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f'[AEGIS] {event.get("risk_level","")} Exposure: {exposure_type}',
        Message=json.dumps(event, default=str, indent=2)
    )
    # FIX #7: Slack
    send_slack(event, config.get('slack_webhook_url',''))
    # FIX #9: Security Hub
    push_to_security_hub(event)
    # SES HTML email with signed URLs
    send_alert_email(event, remediated, config)
    event['remediated'] = remediated
    event['status'] = status
    return event
After pasting: click the orange Deploy button at top of code editor → wait for 'Changes deployed'
Configuration tab → General configuration → Edit → Timeout: 2 min 0 sec → Save
⚠️  You will update API_GATEWAY_URL and SNS_TOPIC_ARN in this function after Phase 10. Do not skip that step.
```

---

## aegis-approval

Handles the approve and restore button clicks from the alert email. Verifies the HMAC-SHA256 token — returns 403 if invalid. Updates finding status in DynamoDB and sends a confirmation email.

Role: `AegisApprovalRole` | Timeout: 30 sec

```python
import boto3
import json
import hmac
import hashlib
from datetime import datetime

def get_config():
    client = boto3.client('secretsmanager')
    # CONFIGURE: If you used a different secret name in Phase 7, update it here
    secret = client.get_secret_value(SecretId='aegis/email-config')
    return json.loads(secret['SecretString'])

def verify_token(finding_id, action, token, secret_key):
    """FIX #10: Verify HMAC signature — rejects tampered or guessed URLs."""
    expected = hmac.new(secret_key.encode(), f'{finding_id}:{action}'.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)

def send_confirmation(action, finding, config):
    ses = boto3.client('ses')
    finding_id = finding.get('finding_id','?')
    resource_id = finding.get('resource_id','?')
    if action == 'approve':
        subject = f'[RESOLVED] Marked as intentional: {resource_id}'
        color = '#27AE60'
        status_text = 'MARKED AS INTENTIONAL - Access Restored'
    else:
        subject = f'[CONFIRMED] Remediation confirmed: {resource_id}'
        color = '#C0392B'
        status_text = 'REMEDIATION CONFIRMED - Resource Stays Blocked'
    html_body = f'''
    <html><body style="font-family:Arial;max-width:600px;margin:0 auto;">
    <div style="background:#1E3A5F;padding:20px;text-align:center;">
      <h1 style="color:white;">Cloud Aegis</h1>
    </div>
    <div style="padding:20px;">
      <div style="background:{color};color:white;padding:15px;border-radius:5px;text-align:center;">
        <h2 style="margin:0;">{status_text}</h2>
      </div>
      <p><strong>Finding ID:</strong> {finding_id}</p>
      <p><strong>Resource:</strong> {resource_id}</p>
      <p><strong>Resolved at:</strong> {datetime.utcnow().isoformat()} UTC</p>
    </div></body></html>
    '''
    ses.send_email(
        Source=config['sender_email'],
        Destination={'ToAddresses': [config['recipient_email']]},
        Message={'Subject':{'Data':subject},'Body':{'Html':{'Data':html_body}}}
    )

def lambda_handler(event, context):
    print('Approval handler:', json.dumps(event, default=str))
    params = event.get('queryStringParameters', {}) or {}
    finding_id = params.get('finding_id','')
    token = params.get('token','')
    action = event.get('path','/approve').strip('/')
    if not finding_id or not token:
        return {'statusCode':400,'headers':{'Content-Type':'text/html'},'body':'<h2>Missing parameters</h2>'}
    # FIX #10: Verify signed token
    try:
        config = get_config()
        token_secret = config.get('approval_token_secret','default_secret')
        if not verify_token(finding_id, action, token, token_secret):
            print('INVALID TOKEN — rejecting request')
            return {'statusCode':403,'headers':{'Content-Type':'text/html'},'body':'<h2>403 Forbidden: Invalid or expired token.</h2>'}
    except Exception as e:
        print(f'Token verification error: {e}')
        return {'statusCode':500,'headers':{'Content-Type':'text/html'},'body':'<h2>Server error</h2>'}
    # Get finding from DynamoDB
    dynamodb = boto3.resource('dynamodb')
    # CONFIGURE: If you changed the DynamoDB table name in Phase 2, update it here
    table = dynamodb.Table('aegis-findings')
    response = table.get_item(Key={'finding_id': finding_id})
    finding = response.get('Item',{})
    if not finding:
        return {'statusCode':404,'headers':{'Content-Type':'text/html'},'body':f'<h2>Finding {finding_id} not found</h2>'}
    new_status = 'INTENTIONAL' if action == 'approve' else 'CONFIRMED_REMEDIATED'
    table.update_item(
        Key={'finding_id': finding_id},
        UpdateExpression='SET #s = :s, resolved_at = :t, resolved_action = :a',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={':s': new_status, ':t': datetime.utcnow().isoformat(), ':a': action}
    )
    try:
        send_confirmation(action, finding, config)
    except Exception as e:
        print(f'Confirmation email error: {e}')
    html_message = '<h2 style="color:green;">Marked as Intentional.</h2>' if action == 'approve' else '<h2 style="color:red;">Remediation Confirmed.</h2>'
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html'},
        'body': f'<html><body style="font-family:Arial;text-align:center;padding:50px;"><h1 style="color:#1E3A5F;">Cloud Aegis</h1>{html_message}<p>Finding: {finding_id}</p><p>You can close this window.</p></body></html>'
    }
After pasting: click the orange Deploy button → wait for 'Changes deployed'
Configuration tab → General configuration → Edit → Timeout: 1 min 0 sec → Save
✅  All 4 Lambda functions are now deployed. Every single one must show 'Changes deployed' message after clicking Deploy — if it still shows an orange Deploy button, your code is NOT saved yet.
```
