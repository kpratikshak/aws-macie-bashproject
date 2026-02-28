#!/bin/bash

################################################################################
# Lambda Function Generator for AWS Macie Automation
#
# Purpose: Generate Lambda function code for automated Macie scanning
#          and object encryption on S3 uploads
#
# Usage:
#   ./create_lambda_function.sh --function-name my-function --bucket my-bucket
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAMBDA_DIR="${SCRIPT_DIR}/lambda_functions"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

mkdir -p "${LAMBDA_DIR}"

################################################################################
# Lambda Function 1: Auto-Encrypt Objects on Upload
################################################################################

create_auto_encrypt_lambda() {
    local function_name=${1:-MacieAutoEncrypt}
    local output_file="${LAMBDA_DIR}/${function_name}.py"
    
    cat > "${output_file}" <<'EOF'
import json
import boto3
import logging
import os

s3_client = boto3.client('s3')
kms_client = boto3.client('kms')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
KMS_KEY_ID = os.environ.get('KMS_KEY_ID', '')  # Set via environment variable
ENCRYPT_BY_DEFAULT = os.environ.get('ENCRYPT_BY_DEFAULT', 'true').lower() == 'true'

def lambda_handler(event, context):
    """
    Auto-encrypt S3 objects on upload.
    
    Event structure:
    {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "bucket-name"},
                    "object": {"key": "object-key"}
                }
            }
        ]
    }
    """
    
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        for record in event.get('Records', []):
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            
            logger.info(f"Processing: s3://{bucket}/{key}")
            
            # Check if object is already encrypted
            if is_encrypted(bucket, key):
                logger.info(f"Object already encrypted: s3://{bucket}/{key}")
                continue
            
            # Encrypt the object
            if KMS_KEY_ID and ENCRYPT_BY_DEFAULT:
                encrypt_with_kms(bucket, key)
                logger.info(f"Encrypted with KMS: s3://{bucket}/{key}")
            elif ENCRYPT_BY_DEFAULT:
                encrypt_with_sse_s3(bucket, key)
                logger.info(f"Encrypted with SSE-S3: s3://{bucket}/{key}")
            else:
                logger.warning(f"Encryption disabled: s3://{bucket}/{key}")
        
        return {
            'statusCode': 200,
            'body': json.dumps('Objects processed successfully')
        }
    
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def is_encrypted(bucket, key):
    """Check if S3 object is encrypted."""
    try:
        response = s3_client.head_object(Bucket=bucket, Key=key)
        encryption = response.get('ServerSideEncryption', 'NONE')
        return encryption != 'NONE'
    except Exception as e:
        logger.error(f"Error checking encryption: {str(e)}")
        return False

def encrypt_with_kms(bucket, key):
    """Encrypt object using KMS."""
    try:
        s3_client.copy_object(
            Bucket=bucket,
            CopySource={'Bucket': bucket, 'Key': key},
            Key=key,
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId=KMS_KEY_ID,
            MetadataDirective='REPLACE'
        )
        return True
    except Exception as e:
        logger.error(f"Error encrypting with KMS: {str(e)}")
        raise

def encrypt_with_sse_s3(bucket, key):
    """Encrypt object using SSE-S3."""
    try:
        s3_client.copy_object(
            Bucket=bucket,
            CopySource={'Bucket': bucket, 'Key': key},
            Key=key,
            ServerSideEncryption='AES256',
            MetadataDirective='REPLACE'
        )
        return True
    except Exception as e:
        logger.error(f"Error encrypting with SSE-S3: {str(e)}")
        raise
EOF
    
    echo -e "${GREEN}✓${NC} Created Lambda function: ${output_file}"
    return 0
}

################################################################################
# Lambda Function 2: Macie Finding Alerts
################################################################################

create_macie_alert_lambda() {
    local function_name=${1:-MacieFindingAlert}
    local output_file="${LAMBDA_DIR}/${function_name}.py"
    
    cat > "${output_file}" <<'EOF'
import json
import boto3
import logging
from datetime import datetime
import os

macie_client = boto3.client('macie2')
sns_client = boto3.client('sns')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SEVERITY_THRESHOLD = os.environ.get('SEVERITY_THRESHOLD', 'MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL

SEVERITY_LEVELS = {
    'LOW': 0,
    'MEDIUM': 1,
    'HIGH': 2,
    'CRITICAL': 3
}

def lambda_handler(event, context):
    """
    Process Macie findings and send alerts via SNS.
    
    Triggered by CloudWatch Events on Macie findings.
    """
    
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract Macie finding details
        detail = event.get('detail', {})
        finding_arn = detail.get('finding-arn', 'Unknown')
        
        # Get detailed finding information
        finding = get_finding_details(finding_arn)
        
        if should_alert(finding):
            alert_message = format_alert(finding)
            send_alert(alert_message)
            logger.info(f"Alert sent for finding: {finding_arn}")
        else:
            logger.info(f"Finding below severity threshold: {finding_arn}")
        
        return {
            'statusCode': 200,
            'body': json.dumps('Finding processed successfully')
        }
    
    except Exception as e:
        logger.error(f"Error processing finding: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def get_finding_details(finding_arn):
    """Get detailed information about a Macie finding."""
    try:
        response = macie_client.get_findings(
            findingIds=[finding_arn.split('/')[-1]]
        )
        
        if response['findings']:
            return response['findings'][0]
        return {}
    except Exception as e:
        logger.error(f"Error retrieving finding: {str(e)}")
        return {}

def should_alert(finding):
    """Determine if finding severity warrants an alert."""
    severity = finding.get('severity', {}).get('description', 'LOW')
    threshold_level = SEVERITY_LEVELS.get(SEVERITY_THRESHOLD, 1)
    finding_level = SEVERITY_LEVELS.get(severity, 0)
    
    return finding_level >= threshold_level

def format_alert(finding):
    """Format finding details for alert message."""
    return f"""
AWS Macie Finding Alert
=======================

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', {}).get('description', 'Unknown')}
Type: {finding.get('type', 'Unknown')}
Created: {finding.get('createdAt', 'Unknown')}

Description:
{finding.get('description', 'No description available')}

Affected Resources:
{json.dumps(finding.get('resourcesAffected', {}), indent=2)}

Details:
{json.dumps(finding.get('findingDetails', {}), indent=2)}

Action Required:
Please review this finding and take appropriate remediation steps.
"""

def send_alert(message):
    """Send alert via SNS."""
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured")
        return
    
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='AWS Macie Security Finding Alert',
            Message=message
        )
    except Exception as e:
        logger.error(f"Error sending SNS message: {str(e)}")
        raise
EOF
    
    echo -e "${GREEN}✓${NC} Created Lambda function: ${output_file}"
    return 0
}

################################################################################
# Lambda Function 3: Periodic Bucket Scan Trigger
################################################################################

create_scan_trigger_lambda() {
    local function_name=${1:-MacieScanTrigger}
    local output_file="${LAMBDA_DIR}/${function_name}.py"
    
    cat > "${output_file}" <<'EOF'
import json
import boto3
import logging
import os
from datetime import datetime

macie_client = boto3.client('macie2')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
BUCKETS_TO_SCAN = os.environ.get('BUCKETS_TO_SCAN', '').split(',')
JOB_NAME_PREFIX = os.environ.get('JOB_NAME_PREFIX', 'periodic-scan')

def lambda_handler(event, context):
    """
    Trigger periodic Macie scan jobs for configured buckets.
    
    Triggered by CloudWatch Events (e.g., daily schedule).
    Event structure: Can be scheduled rule with optional bucket list.
    """
    
    logger.info(f"Starting scheduled scan jobs")
    
    try:
        # Get buckets from event or environment
        buckets = get_buckets_to_scan(event)
        
        if not buckets:
            logger.warning("No buckets specified for scanning")
            return {'statusCode': 400, 'body': 'No buckets to scan'}
        
        created_jobs = []
        
        for bucket in buckets:
            try:
                job_id = create_scan_job(bucket)
                created_jobs.append({'bucket': bucket, 'jobId': job_id})
                logger.info(f"Created scan job for bucket: {bucket} (Job ID: {job_id})")
            except Exception as e:
                logger.error(f"Failed to create scan job for {bucket}: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan jobs created successfully',
                'jobsCreated': created_jobs,
                'timestamp': datetime.utcnow().isoformat()
            })
        }
    
    except Exception as e:
        logger.error(f"Error creating scan jobs: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def get_buckets_to_scan(event):
    """Get list of buckets to scan from event or environment."""
    # Check if buckets are in the event
    buckets = event.get('buckets', [])
    
    if buckets:
        return buckets
    
    # Fall back to environment variable
    return [b.strip() for b in BUCKETS_TO_SCAN if b.strip()]

def get_account_id():
    """Get AWS account ID."""
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account']

def create_scan_job(bucket):
    """Create a Macie classification job for the specified bucket."""
    
    account_id = get_account_id()
    job_name = f"{JOB_NAME_PREFIX}-{bucket}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    
    response = macie_client.create_classification_job(
        bucketDefinitions=[
            {
                'accountId': account_id,
                'buckets': [bucket]
            }
        ],
        jobType='DISCOVERY_JOB',
        name=job_name,
        description=f'Automated periodic scan for {bucket}',
        managedDataIdentifierSelector='ALL',
        samplingPercentage=100
    )
    
    return response['jobId']
EOF
    
    echo -e "${GREEN}✓${NC} Created Lambda function: ${output_file}"
    return 0
}

################################################################################
# IAM Inline Policy for Lambda
################################################################################

create_lambda_iam_policy() {
    local output_file="${LAMBDA_DIR}/lambda_iam_policy.json"
    
    cat > "${output_file}" <<'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3Permissions",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::*/*"
        },
        {
            "Sid": "KMSPermissions",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "arn:aws:kms:*:*:key/*"
        },
        {
            "Sid": "MaciePermissions",
            "Effect": "Allow",
            "Action": [
                "macie2:GetMacieSession",
                "macie2:GetFindings",
                "macie2:ListFindings",
                "macie2:CreateClassificationJob",
                "macie2:DescribeClassificationJob"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SNSPermissions",
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:*:*:*"
        },
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
EOF
    
    echo -e "${GREEN}✓${NC} Created IAM policy: ${output_file}"
    return 0
}

################################################################################
# CloudFormation Template
################################################################################

create_cloudformation_template() {
    local output_file="${LAMBDA_DIR}/macie_automation_stack.yaml"
    
    cat > "${output_file}" <<'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: 'CloudFormation template for automated AWS Macie S3 encryption'

Parameters:
  BucketNames:
    Type: CommaDelimitedList
    Description: List of S3 bucket names to protect
    Default: bucket1,bucket2

  KMSKeyId:
    Type: String
    Description: KMS key ID for encryption (leave empty for SSE-S3)
    Default: ''

  SNSTopicEmail:
    Type: String
    Description: Email address for Macie finding alerts

Resources:
  # IAM Role for Lambda Functions
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: MacieLambdaExecutionRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: MacieS3KMSPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:GetObjectVersion
                  - s3:PutObject
                Resource: 'arn:aws:s3:::*/*'
              - Effect: Allow
                Action:
                  - kms:Decrypt
                  - kms:Encrypt
                  - kms:ReEncrypt*
                  - kms:GenerateDataKey*
                Resource: 'arn:aws:kms:*:*:key/*'
              - Effect: Allow
                Action:
                  - macie2:*
                Resource: '*'
              - Effect: Allow
                Action:
                  - sns:Publish
                Resource: !Ref AlertTopic

  # SNS Topic for Alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: MacieSecurityAlerts
      Subscription:
        - Endpoint: !Ref SNSTopicEmail
          Protocol: email

  # Lambda Function for Auto-Encryption
  AutoEncryptFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: MacieAutoEncrypt
      Runtime: python3.9
      Handler: index.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Environment:
        Variables:
          KMS_KEY_ID: !Ref KMSKeyId
          ENCRYPT_BY_DEFAULT: 'true'
      Code:
        ZipFile: |
          # Lambda code here (see separate Lambda functions)

  # S3 Event Notification
  S3EventNotification:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: dummy
      NotificationConfiguration:
        LambdaFunctionConfigurations:
          - Event: s3:ObjectCreated:*
            Function: !GetAtt AutoEncryptFunction.Arn

  # Lambda Permission for S3
  S3InvokeLambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref AutoEncryptFunction
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com
      SourceArn: !Sub 'arn:aws:s3:::${BucketNames}'

  # CloudWatch Rule for Periodic Scans
  PeriodicScanRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Trigger Macie scans daily
      ScheduleExpression: cron(0 2 * * ? *)
      State: ENABLED
      Targets:
        - Arn: !GetAtt ScanTriggerFunction.Arn
          Id: MacieScanTrigger

  # Lambda Permission for CloudWatch
  CloudWatchInvokeLambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref ScanTriggerFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt PeriodicScanRule.Arn

  # Scan Trigger Function
  ScanTriggerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: MacieScanTrigger
      Runtime: python3.9
      Handler: index.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Environment:
        Variables:
          BUCKETS_TO_SCAN: !Join [',', !Ref BucketNames]
      Code:
        ZipFile: |
          # Lambda code here (see separate Lambda functions)

Outputs:
  AlertTopicArn:
    Description: SNS Topic ARN for Macie alerts
    Value: !Ref AlertTopic
    Export:
      Name: MacieAlertTopic

  AutoEncryptFunctionArn:
    Description: ARN of auto-encrypt Lambda function
    Value: !GetAtt AutoEncryptFunction.Arn

  ScanTriggerFunctionArn:
    Description: ARN of scan trigger Lambda function
    Value: !GetAtt ScanTriggerFunction.Arn
EOF
    
    echo -e "${GREEN}✓${NC} Created CloudFormation template: ${output_file}"
    return 0
}

################################################################################
# Deployment Instructions
################################################################################

create_deployment_guide() {
    local output_file="${LAMBDA_DIR}/DEPLOYMENT_GUIDE.md"
    
    cat > "${output_file}" <<'EOF'
# Lambda Function Deployment Guide

## Overview

This guide explains how to deploy the Lambda functions for automated Macie and S3 encryption.

## Prerequisites

- AWS CLI installed and configured
- IAM permissions to create Lambda functions and IAM roles
- Python 3.9+ for local testing

## Method 1: Using CloudFormation (Recommended)

```bash
# Deploy the CloudFormation stack
aws cloudformation create-stack \
    --stack-name macie-automation \
    --template-body file://macie_automation_stack.yaml \
    --parameters \
        ParameterKey=BucketNames,ParameterValue=bucket1,bucket2 \
        ParameterKey=SNSTopicEmail,ParameterValue=your-email@example.com \
    --capabilities CAPABILITY_NAMED_IAM

# Monitor deployment
aws cloudformation describe-stacks \
    --stack-name macie-automation \
    --query 'Stacks[0].StackStatus'

# Get outputs
aws cloudformation describe-stacks \
    --stack-name macie-automation \
    --query 'Stacks[0].Outputs'
```

## Method 2: Manual Lambda Deployment

### Step 1: Create IAM Role

```bash
# Create role
aws iam create-role \
    --role-name MacieLambdaExecutionRole \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'

# Attach policy
aws iam put-role-policy \
    --role-name MacieLambdaExecutionRole \
    --policy-name MaciePolicy \
    --policy-document file://lambda_iam_policy.json

# Attach basic execution role
aws iam attach-role-policy \
    --role-name MacieLambdaExecutionRole \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

### Step 2: Create Lambda Function Package

```bash
# Create function package
mkdir -p /tmp/lambda
cp MacieAutoEncrypt.py /tmp/lambda/index.py

# Create ZIP file
cd /tmp/lambda
zip -r ../macie-auto-encrypt.zip .
cd -

# Create function
aws lambda create-function \
    --function-name MacieAutoEncrypt \
    --runtime python3.9 \
    --handler index.lambda_handler \
    --role arn:aws:iam::ACCOUNT_ID:role/MacieLambdaExecutionRole \
    --zip-file fileb:///tmp/macie-auto-encrypt.zip \
    --environment Variables={KMS_KEY_ID=arn:aws:kms:...,ENCRYPT_BY_DEFAULT=true}
```

### Step 3: Configure S3 Event Notifications

```bash
# Create notification configuration
cat > /tmp/s3-notification.json <<EOF
{
    "LambdaFunctionConfigurations": [
        {
            "LambdaFunctionArn": "arn:aws:lambda:REGION:ACCOUNT_ID:function:MacieAutoEncrypt",
            "Events": ["s3:ObjectCreated:*"]
        }
    ]
}
EOF

# Apply configuration
aws s3api put-bucket-notification-configuration \
    --bucket my-bucket \
    --notification-configuration file:///tmp/s3-notification.json

# Grant Lambda permission
aws lambda add-permission \
    --function-name MacieAutoEncrypt \
    --statement-id AllowS3Invoke \
    --action lambda:InvokeFunction \
    --principal s3.amazonaws.com \
    --source-arn arn:aws:s3:::my-bucket
```

### Step 4: Configure CloudWatch Rules for Periodic Scans

```bash
# Create CloudWatch rule
aws events put-rule \
    --name periodic-macie-scan \
    --schedule-expression "cron(0 2 * * ? *)" \
    --state ENABLED \
    --description "Daily Macie scan at 2 AM UTC"

# Add Lambda target
aws events put-targets \
    --rule periodic-macie-scan \
    --targets "Id"="1","Arn"="arn:aws:lambda:REGION:ACCOUNT_ID:function:MacieScanTrigger","RoleArn"="arn:aws:iam::ACCOUNT_ID:role/EventBridgeRole"

# Grant permission
aws lambda add-permission \
    --function-name MacieScanTrigger \
    --statement-id AllowCloudWatchInvoke \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/periodic-macie-scan
```

## Testing

### Test Auto-Encrypt Lambda

```bash
# Create test event
cat > /tmp/test-event.json <<EOF
{
    "Records": [
        {
            "s3": {
                "bucket": {"name": "my-bucket"},
                "object": {"key": "test-file.txt"}
            }
        }
    ]
}
EOF

# Invoke function
aws lambda invoke \
    --function-name MacieAutoEncrypt \
    --payload file:///tmp/test-event.json \
    /tmp/response.json

# Check response
cat /tmp/response.json
```

### Test Scan Trigger Lambda

```bash
# Create test event
cat > /tmp/scan-test.json <<EOF
{
    "buckets": ["my-bucket"]
}
EOF

# Invoke function
aws lambda invoke \
    --function-name MacieScanTrigger \
    --payload file:///tmp/scan-test.json \
    /tmp/response.json

# Check response
cat /tmp/response.json
```

## Monitoring

### View CloudWatch Logs

```bash
# Get latest logs
aws logs tail /aws/lambda/MacieAutoEncrypt --follow

# Filter for errors
aws logs filter-log-events \
    --log-group-name /aws/lambda/MacieAutoEncrypt \
    --filter-pattern "ERROR"
```

### Monitor Lambda Metrics

```bash
# Get invocations in last hour
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Invocations \
    --dimensions Name=FunctionName,Value=MacieAutoEncrypt \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 3600 \
    --statistics Sum
```

## Troubleshooting

### Lambda function returns timeout error

- Increase timeout: `aws lambda update-function-configuration --function-name NAME --timeout 60`

### Lambda cannot access S3

- Check IAM role permissions
- Verify S3 bucket access

### Lambda cannot access KMS

- Check KMS key policy allows Lambda role
- Verify key ARN is correct

### CloudWatch Events not triggering

- Check rule is enabled: `aws events describe-rule --name periodic-macie-scan`
- Check targets: `aws events list-targets-by-rule --rule periodic-macie-scan`

## Cleanup

```bash
# Delete stack
aws cloudformation delete-stack --stack-name macie-automation

# OR manual cleanup:
# Delete Lambda functions
aws lambda delete-function --function-name MacieAutoEncrypt
aws lambda delete-function --function-name MacieScanTrigger

# Delete IAM role
aws iam delete-role-policy --role-name MacieLambdaExecutionRole --policy-name MaciePolicy
aws iam delete-role --role-name MacieLambdaExecutionRole

# Delete CloudWatch rule
aws events remove-targets --rule periodic-macie-scan --ids "1"
aws events delete-rule --name periodic-macie-scan
```

EOF
    
    echo -e "${GREEN}✓${NC} Created deployment guide: ${output_file}"
    return 0
}

################################################################################
# Main Function
################################################################################

main() {
    echo -e "${BLUE}Creating Lambda Functions for AWS Macie Automation${NC}\n"
    
    create_auto_encrypt_lambda "MacieAutoEncrypt"
    create_macie_alert_lambda "MacieFindingAlert"
    create_scan_trigger_lambda "MacieScanTrigger"
    create_lambda_iam_policy
    create_cloudformation_template
    create_deployment_guide
    
    echo -e "\n${GREEN}✓ All Lambda functions created successfully!${NC}"
    echo -e "\nOutput directory: ${LAMBDA_DIR}"
    echo -e "\nNext steps:"
    echo -e "1. Review the functions in ${LAMBDA_DIR}/"
    echo -e "2. Read the deployment guide: ${LAMBDA_DIR}/DEPLOYMENT_GUIDE.md"
    echo -e "3. Deploy using CloudFormation or manually"
    echo -e "4. Configure environment variables for your setup"
    echo -e "\n${BLUE}Quick Start:${NC}"
    echo -e "aws cloudformation create-stack \\"
    echo -e "  --stack-name macie-automation \\"
    echo -e "  --template-body file://${LAMBDA_DIR}/macie_automation_stack.yaml \\"
    echo -e "  --parameters ParameterKey=BucketNames,ParameterValue=my-bucket \\"
    echo -e "  --capabilities CAPABILITY_NAMED_IAM"
}

main
