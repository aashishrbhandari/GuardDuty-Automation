terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.0.1"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# The attribute `${data.aws_caller_identity.current.account_id}` will be current account number.
data "aws_caller_identity" "current" {}

# The attribute `${data.aws_region.current.name}` will be current region
data "aws_region" "current" {}

# Random String (To Invoke Lambda Function)
resource "random_string" "random_data" {
    length = 16
}

/** Step 0: Get the ENV Variable holding Slack Webhook URL (Minimum) **/

variable "SLACK_WEBHOOK_URL" {
    type = string
}

variable "ELASTIC_FLEET_URL" {
    type = string
}

variable "ELASTIC_ENROLLMENT_TOKEN" {
    type = string
}

variable "TERRAFORM_STATE_FILE_STATUS" {
    type = string
    description = "Did you delete the Terraform State file?"
}

# AWS Lambda Function Name (Guardduty)
variable "lambda_function_name" {
    default = "GuardDutyAlert"
}


/** Step 1: Create S3 Bucket to Store GuardDuty Logs **/

# Create S3 Bucket for GuardDuty Events
resource "aws_s3_bucket" "guardduty_s3_bucket" {
    bucket_prefix        = "aws-guardduty-export"
}

# Policy Document to Allow GuardDuty to Export Events to S3 Bucket
data "aws_iam_policy_document" "guardduty_s3_bucket_policy_document" {
    statement {
        sid = "GuardDutyServicePutToS3"
        effect = "Allow"
        actions = [
            "s3:PutObject",
            "s3:GetBucketLocation"
        ]

        resources = [
            "${aws_s3_bucket.guardduty_s3_bucket.arn}/*",
            aws_s3_bucket.guardduty_s3_bucket.arn
        ]

        principals {
            type        = "Service"
            identifiers = ["guardduty.amazonaws.com"]
        }
    }
}

# Set the above Policy Document to the Respective GuardDuty S3 Bucket 
resource "aws_s3_bucket_policy" "guardduty_s3_bucket_policy" {
  bucket        = aws_s3_bucket.guardduty_s3_bucket.id
  policy        = data.aws_iam_policy_document.guardduty_s3_bucket_policy_document.json
}


/** Step 2: Create KMS Key & add Required Permissions **/

# Create KMS Key
resource "aws_kms_key" "guardduty_s3_encrypt_kms_key" {
    description             = "Used by GuardDuty to Encrypt and Store the GuardDuty Events on S3"   
}

# Policy Document to Allow GuardDuty to GenerateDataKey to be used to Encrypt S3 Events
data "aws_iam_policy_document" "guardduty_s3_encrypt_kms_key_policy_document" {
    
    statement {
        sid = "Allow Root User to Access the Key"
        effect = "Allow"
        actions = [
            "kms:*"
        ]

        resources = [
            aws_kms_key.guardduty_s3_encrypt_kms_key.arn
        ]

        principals {
            type        = "AWS"
            identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
        }
    }
    
    statement {
        sid = "Allow GuardDuty to Encrypt findings"
        effect = "Allow"
        actions = [
            "kms:GenerateDataKey"
        ]

        resources = [
            aws_kms_key.guardduty_s3_encrypt_kms_key.arn
        ]

        principals {
            type        = "Service"
            identifiers = ["guardduty.amazonaws.com"]
        }
    }
    
}

# Set the KMS Policy to the Respective GuardDuty KMS Key 
resource "aws_kms_key_policy" "guardduty_s3_encrypt_kms_key_policy" {
    key_id                  = aws_kms_key.guardduty_s3_encrypt_kms_key.key_id
    policy                  = data.aws_iam_policy_document.guardduty_s3_encrypt_kms_key_policy_document.json
}

# Set the an ALIAS name to GuardDuty KMS Key // EXTRA
resource "aws_kms_alias" "guardduty_kms_alias_name" {
  name          = "alias/guardduty/GuardDuty-S3-Store-Key"
  target_key_id = aws_kms_key.guardduty_s3_encrypt_kms_key.key_id
}


/** Step 3: Enable GuardDuty **/

resource "aws_guardduty_detector" "guardduty_detector_idps" {
    enable                          = true
    finding_publishing_frequency    = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_publishing_destination" "guardduty_s3_export_settings" {
    detector_id     = aws_guardduty_detector.guardduty_detector_idps.id
    destination_arn = aws_s3_bucket.guardduty_s3_bucket.arn
    kms_key_arn     = aws_kms_key.guardduty_s3_encrypt_kms_key.arn

    depends_on = [
        aws_s3_bucket_policy.guardduty_s3_bucket_policy
    ]
}


/** Step 4: Create Lambda Function to handle GuardDuty Alert and Send Email **/

# Create ZIP of the Python Code inside Dir: `py_code`
data "archive_file" "guardduty_py_zip" {
    type        = "zip"
    source_dir = "../py_code"
    output_path = "guardduty_alerts_slack.zip"
}

# Lambda Assume Role Document
data "aws_iam_policy_document" "lambda_assume_role" {
    statement {
        effect = "Allow"

        principals {
            type        = "Service"
            identifiers = ["lambda.amazonaws.com"]
        }

        actions = ["sts:AssumeRole"]
    }
}

# Lambda CloudWatch Permissions
resource "aws_iam_policy" "lambda_allow_putlogs_to_cloudwatch" {
    name = "Lambda_Allow_PutLogs_To_CloudWatch"

    policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCreateLogGroup",
                "Effect": "Allow",
                "Action": "logs:CreateLogGroup",
                "Resource": "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            },
            {
                "Sid": "RestrictedLogPutAccess",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": [
                    "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.lambda_function_name}:*"
                ]
            }
        ]
    })
}

# Attach IAM Role to Lambda Function
resource "aws_iam_role" "iam_for_lambda" {
    name                = "iam_for_lambda"
    assume_role_policy  = data.aws_iam_policy_document.lambda_assume_role.json
    managed_policy_arns = [aws_iam_policy.lambda_allow_putlogs_to_cloudwatch.arn]
}

# Create Lambda Function , Attaching the ZIP file as the Py Code
resource "aws_lambda_function" "guardduty_lambda_alert" {

    filename      = "guardduty_alerts_slack.zip"
    function_name = var.lambda_function_name
    description   = "Handles GuardDuty Alert Received from EventBridge and Alerts Security Team"
    role          = aws_iam_role.iam_for_lambda.arn
    handler       = "guardduty_alerts_slack.lambda_handler"

    source_code_hash = data.archive_file.guardduty_py_zip.output_base64sha256

    runtime = "python3.9"

    # Received from ENV Variable TF_VAR_SLACK_WEBHOOK_URL
    environment {
        variables = {
            SLACK_WEBHOOK_URL = var.SLACK_WEBHOOK_URL,
            RANDOM_STRING     = random_string.random_data.result
        }
    }

}

# Testing Lambda Function: Invoke Lambda Function (use random_string to invoke it every time we do `terraform apply`)
resource "aws_lambda_invocation" "guardduty_lambda_alert_invoke" {
    function_name = aws_lambda_function.guardduty_lambda_alert.function_name

    triggers = {
        redeployment = sha1(jsonencode([
            aws_lambda_function.guardduty_lambda_alert.environment
        ]))
    }

    input = <<-EOF
        {
            "version": "0",
            "id": "71561e54-7959-62b0-03b3-537d8b23848d",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "000000000000",
            "time": "2023-09-09T12:40:02Z",
            "region": "us-east-1",
            "resources": [],
            "detail": {
                "schemaVersion": "2.0",
                "accountId": "000000000000",
                "region": "us-east-1",
                "partition": "aws",
                "id": "02c53cf9980d6ac6c353a5734f4a4b19",
                "arn": "arn:aws:guardduty:us-east-1:000000000000:detector/54c53cee661562b4f19056104078daef/finding/02c53cf9980d6ac6c353a5734f4a4b19",
                "type": "InvokeSuccess:TestLambdaEvent",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": "i-08f7ba1639386c53e",
                        "instanceType": "t2.micro",
                        "launchTime": "2023-09-09T12:13:58.000Z",
                        "platform": null,
                        "productCodes": [],
                        "iamInstanceProfile": {
                            "arn": "arn:aws:iam::000000000000:instance-profile/ec2_profile",
                            "id": "AIPAWL2YUJ2BNYXIMHXDS"
                        },
                        "networkInterfaces": [
                            {
                                "ipv6Addresses": [],
                                "networkInterfaceId": "eni-02e8bb9905010bea9",
                                "privateDnsName": "ip-172-31-47-181.ec2.internal",
                                "privateIpAddress": "172.31.47.181",
                                "privateIpAddresses": [
                                    {
                                        "privateDnsName": "ip-172-31-47-181.ec2.internal",
                                        "privateIpAddress": "172.31.47.181"
                                    }
                                ],
                                "subnetId": "subnet-081b2334b057ef84a",
                                "vpcId": "vpc-04042fb07cd336f5d",
                                "securityGroups": [
                                    {
                                        "groupName": "Ec2_Access SG",
                                        "groupId": "sg-0a9e2a25fc21b46e3"
                                    }
                                ],
                                "publicDnsName": "ec2-35-153-104-199.compute-1.amazonaws.com",
                                "publicIp": "35.153.104.199"
                            }
                        ],
                        "outpostArn": null,
                        "tags": [
                            {
                                "key": "Name",
                                "value": "Attacker_Machine"
                            }
                        ],
                        "instanceState": "running",
                        "availabilityZone": "us-east-1d",
                        "imageId": "ami-0715c1897453cabd1",
                        "imageDescription": "Amazon Linux 2023 AMI 2023.0.20230517.1 x86_64 HVM kernel-6.1"
                    }
                },
                "service": {
                    "serviceName": "guardduty",
                    "detectorId": "54c53cee661562b4f19056104078daef",
                    "action": {
                        "actionType": "DNS_REQUEST",
                        "dnsRequestAction": {
                            "domain": "0mbbcenpjyobgcbvgiggudgbwyfprprcciwmigq8oybc6tnw0igz83mugcuaj6.ximdiymhfwmdsbctfuq9xkygaq59fsoxzawfbt2qthv7bjxloxle_jvvc.pmp243ppxp-z26aaahh6u.fillit.thisdomaindoesnotexists.com",
                            "protocol": "0",
                            "blocked": false
                        }
                    },
                    "resourceRole": "TARGET",
                    "additionalInfo": {
                        "domain": "0mbbcenpjyobgcbvgiggudgbwyfprprcciwmigq8oybc6tnw0igz83mugcuaj6.ximdiymhfwmdsbctfuq9xkygaq59fsoxzawfbt2qthv7bjxloxle_jvvc.pmp243ppxp-z26aaahh6u.fillit.thisdomaindoesnotexists.com",
                        "value": "{\"domain\":\"0mbbcenpjyobgcbvgiggudgbwyfprprcciwmigq8oybc6tnw0igz83mugcuaj6.ximdiymhfwmdsbctfuq9xkygaq59fsoxzawfbt2qthv7bjxloxle_jvvc.pmp243ppxp-z26aaahh6u.fillit.thisdomaindoesnotexists.com\"}",
                        "type": "default"
                    },
                    "eventFirstSeen": "2023-09-09T12:19:08.000Z",
                    "eventLastSeen": "2023-09-09T12:19:08.000Z",
                    "archived": false,
                    "count": 1
                },
                "severity": 8,
                "createdAt": "2023-09-09T12:38:15.322Z",
                "updatedAt": "2023-09-09T12:38:15.322Z",
                "title": "Data exfiltration through DNS queries from EC2 instance i-08f7ba1639386c53e.",
                "description": "InvokeSuccess:TestLambdaEvent - This is an Test Event created to Validate the Lambda Trigger and Alert on Slack."
            }
        }

    EOF
}

/** Step 5: Create AWS EventBridge Rule for GuardDuty Events **/

# AWS EventBridge Rule // CloudWatch Event
resource "aws_cloudwatch_event_rule" "guardduty_eventbridge_rule" {
    name        = "GuardDuty_EventBridge_Rule"
    description = "Capture All GuardDuty Events"

    event_pattern = jsonencode({
        "source": ["aws.guardduty"],
        "detail-type": ["GuardDuty Finding", "GuardDuty Runtime Protection Unhealthy", "GuardDuty Runtime Protection Healthy"]
    })
}

# Setup Event Target for the Above Rule (Target: Lambda Function)
resource "aws_cloudwatch_event_target" "guardduty_eventbridge_rule_target_lambda" {
    arn  = aws_lambda_function.guardduty_lambda_alert.arn
    rule = aws_cloudwatch_event_rule.guardduty_eventbridge_rule.id
}

# AWS Eventbridge to Invoke Lambda Function
resource "aws_lambda_permission" "allow_eventbridge_rule_to_call_lambda_function" {
    statement_id = "AllowInvokeFunctionFromEventBridge"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.guardduty_lambda_alert.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.guardduty_eventbridge_rule.arn
}

/** Step 6: Instance Creation, Attacker Script Upload, to Test the Above Guardduty Automation **/

# AWS S3 Bucket to store the Attacker Scripts
resource "aws_s3_bucket" "attacker_scripts" {
    bucket_prefix = "attacker-scripts"
}

# Upload the Script to AWS S3 Bucket
resource "aws_s3_object" "attacker_scripts_upload" {
    for_each = fileset("../sh_code/", "*")
    bucket = aws_s3_bucket.attacker_scripts.id
    key = each.value
    source = "../sh_code/${each.value}"
    etag = filemd5("../sh_code/${each.value}")
}

# Security Group / Firewall for AWS EC2
resource "aws_security_group" "aws_ec2_access_sg" {
    name = "EC2_Access SG"

    ingress {
        description = "SSH from the internet"
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "80 from the internet"
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

}

# AWS IAM Role for EC2 Instance
resource "aws_iam_role" "attacker_machine_ec2_role" {
    name        = "Attacker_Machine_EC2_Role"
    description = "Attacker Machine EC2 Role"
    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    })
}

# IAM Permission Required by Script
resource "aws_iam_policy" "ec2_script_permissions" {
    name = "EC2_Script_Permissions"

    description = "EC2 Script Permissions"

    policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CURDBucketRestrictedAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:CreateBucket*",
                    "s3:PutBucketPublicAccessBlock",
                    "s3:PutBucketPolicy"
                ],
                "Resource": [
                    "arn:aws:s3:::creds-apps-built-*"
                ]
            },
            {
                "Sid": "GuardDutyAndEC2RestrictedAccess",
                "Effect": "Allow",
                "Action": [
                    "guardduty:CreateSampleFindings",
                    "guardduty:ListDetectors",
                    "ec2:DescribeInstances"
                ],
                "Resource": [
                    "*"
                ]
            },
            {
                "Sid": "AttackerScriptsBucketROAccess",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket*"
                ],
                "Effect": "Allow",
                "Resource": [
                    "${aws_s3_bucket.attacker_scripts.arn}",
                    "${aws_s3_bucket.attacker_scripts.arn}/*"
                ]
            }
        ]
    })
}

# Attach AWS IAM Policy to the IAM Role
resource "aws_iam_role_policy_attachment" "ec2_script_permissions_attachment" {
    role       = aws_iam_role.attacker_machine_ec2_role.name
    policy_arn = aws_iam_policy.ec2_script_permissions.arn
}

# Create Instance Role from IAM Role
resource "aws_iam_instance_profile" "attacker_machine_ec2_profile" {
    name = "Attacker_Machine_EC2_Profile"
    role = aws_iam_role.attacker_machine_ec2_role.name
}

# AWS IAM Role for EC2 Instance [Elastic Agent]
resource "aws_iam_role" "elastic_agent_ec2_role" {
    name        = "Elastic_Agent_EC2_Role"
    description = "Instance Role used by Elastic Agent"
    assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    })
}

# IAM Permission Required by Elastic Agent Node - To Pull S3 Objects (GuardDuty Alert Events) [Elastic Agent]
resource "aws_iam_policy" "elastic_agent_permission" {
    name = "Elastic_Agent_Permission"

    policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [            
            {
                "Action": [
                    "kms:Decrypt"
                ],
                "Effect": "Allow",
                "Resource": "${aws_kms_key.guardduty_s3_encrypt_kms_key.arn}"
            },
            {
                "Action": [
                    "s3:GetBucketLocation"
                ],
                "Effect": "Allow",
                "Resource": "*"
            },
            {
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket*"
                ],
                "Effect": "Allow",
                "Resource": [
                    "${aws_s3_bucket.guardduty_s3_bucket.arn}",
                    "${aws_s3_bucket.guardduty_s3_bucket.arn}/*"
                ]
            }
        ]
    })
}

# Attach AWS IAM Policy to the IAM Role [Elastic Agent]
resource "aws_iam_role_policy_attachment" "elastic_agent_permission_attachment" {
    role       = aws_iam_role.elastic_agent_ec2_role.name
    policy_arn = aws_iam_policy.elastic_agent_permission.arn
}

# Create Instance Role from IAM Role [Elastic Agent]
resource "aws_iam_instance_profile" "elastic_agent_ec2_profile" {
    name = "Elastic_Agent_EC2_Profile"
    role = aws_iam_role.elastic_agent_ec2_role.name
}

# AWS EC2 Machine from where we can run our Attacker Script which Trickers GuardDuty Alerts
resource "aws_instance" "aws_instance_for_attacker" {
    ami                         = "ami-0715c1897453cabd1"
    instance_type               = "t2.micro"
    vpc_security_group_ids      = [aws_security_group.aws_ec2_access_sg.id]
    associate_public_ip_address = true
    iam_instance_profile = aws_iam_instance_profile.attacker_machine_ec2_profile.name

    user_data = <<-EOF
        #! /bin/bash
        #sudo yum update
        sudo mkdir -p /usr/local/src/attacker_scripts
        sudo aws s3 sync s3://"${aws_s3_bucket.attacker_scripts.id}"/ /usr/local/src/attacker_scripts/
        sudo yum install httpd nmap -y
        sudo systemctl enable --now httpd
        echo '#!/bin/bash
        echo Content-type: text/plain
        echo
        bash /usr/local/src/attacker_scripts/guardduty-setup-qa.sh' > /var/www/cgi-bin/attacker.sh
        sudo systemctl reload httpd
        sudo chmod +x /var/www/cgi-bin/attacker.sh
        echo "${random_string.random_data.result}"
	EOF

    user_data_replace_on_change = true

    tags = {
        Name = "Attacker_Machine"
    }
}

# AWS EC2 for Victim Node
resource "aws_instance" "aws_instance2_for_victim" {
    ami                         = "ami-0715c1897453cabd1"
    instance_type               = "t2.micro"
    vpc_security_group_ids      = [aws_security_group.aws_ec2_access_sg.id]
    associate_public_ip_address = true
    
    user_data = <<-EOF
        #! /bin/bash
        sudo yum install httpd -y
        sudo systemctl enable --now httpd
        echo "${random_string.random_data.result}"
	EOF

    user_data_replace_on_change = true

    tags = {
        Name = "Victim_Machine"
    }
}



# Elastic Stack Integration Node, Dummy Value can be Set if Elastic Stack Integration and Dashboard access is not Required.
resource "aws_instance" "aws_instance_for_elastic" {
    ami                         = "ami-0715c1897453cabd1"
    instance_type               = "t2.micro"
    vpc_security_group_ids      = [aws_security_group.aws_ec2_access_sg.id]
    associate_public_ip_address = true
    iam_instance_profile = aws_iam_instance_profile.elastic_agent_ec2_profile.name

    # Received from ENV Variable TF_VAR_ELASTIC_FLEET_URL & TF_VAR_ELASTIC_ENROLLMENT_TOKEN
    user_data = <<-EOF
        #! /bin/bash
        echo "Newly Added" >> /etc/motd
        sudo yum install docker -y
        sudo systemctl enable --now docker
        docker run -d \
            -h "GuardDuty.Collector" \
            --env FLEET_ENROLL=1 \
            --env FLEET_URL=${var.ELASTIC_FLEET_URL} \
            --env FLEET_ENROLLMENT_TOKEN=${var.ELASTIC_ENROLLMENT_TOKEN} \
            --rm docker.elastic.co/beats/elastic-agent:8.8.0
        echo "${random_string.random_data.result}"
	EOF

    user_data_replace_on_change = true

    tags = {
        Name = "ElasticAgent_Machine"
    }
}

/** OutPut IMP Fields **/

output "guardduty_detector_s3" {
    value = aws_s3_bucket.guardduty_s3_bucket.id
    description = "AWS S3 Bucket where GuardDuty Event Logs are Stored"
}

output "guardduty_attacker_script" {
    value = "http://${aws_instance.aws_instance_for_attacker.public_ip}/cgi-bin/attacker.sh"
    description = "Attacker Machine - Script URL, Open in Private Windows to Execute Attack and Test"
}

output "guardduty_lambda_alert_invoke_result" {
  value = aws_lambda_invocation.guardduty_lambda_alert_invoke.result
  description = "GUardduty Lambda Alert Invoke Result"
}