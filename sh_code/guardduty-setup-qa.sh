#!/bin/bash

AWS_STS_DETAILS=$(aws sts get-caller-identity --output text)

TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

# Get Current Machines

echo "[+] Current EC2 Machine IAM Role Temprorary Creds!!! Use it to Trigger GuardDuty Alerts";

INSTANCE_ROLE=`curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/`

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/${INSTANCE_ROLE}

# Get Current Machines Private IP
MY_IP_ADDR=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)

###############################################################################################################

# Run Nmap Scan for the Victim Host
for ONE_EC2_IP in $(aws ec2 describe-instances --query "Reservations[].Instances[].PrivateIpAddress" --output text | tr "\t" "\n"); 
do 
    if [[ $ONE_EC2_IP != $MY_IP_ADDR ]];
    then
        echo "[+] Victim Machine IP is : $ONE_EC2_IP , Running Internal NMAP Scan";
        nmap -sT $ONE_EC2_IP;
    fi
done

###############################################################################################################

# EXAMPLE : creds-apps-built-000000000-df22a66f1083613f41e69625
BUCKET_PREFIX="creds-apps-built";
BUCKET_MIDDLE=$(echo "${AWS_STS_DETAILS}" | cut -d $'\t' -f1)
BUCKET_SUFFIX=$(echo $RANDOM | md5sum | head -c 24 |  tr '[:upper:]' '[:lower:]');

BUCKET_NAME=$BUCKET_PREFIX-$BUCKET_MIDDLE-$BUCKET_SUFFIX 

echo "[+] Creating an Publically Exposed AWS S3 Bucket ${BUCKET_NAME}" 

# Create S3 Bucket
aws s3api create-bucket --bucket $BUCKET_NAME

# Disable / Rempve `Block all public access` 
aws s3api put-public-access-block --bucket $BUCKET_NAME --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

# Create Bucket ACL to Allow All Objects READ from Anyone --- Making Bucket completely PUBLIC
aws s3api put-bucket-policy --bucket ${BUCKET_NAME} --policy '{"Version":"2008-10-17","Statement":[{"Sid":"AllowPublicRead","Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::'"${BUCKET_NAME}"'/*"]}]}'

###############################################################################################################

echo "[+] Calling large numbers of large domains to simulate tunneling via DNS"

SCRIPT_FULL_PATH=$(realpath $0)
SCRIPT_PATH=$(dirname ${SCRIPT_FULL_PATH})
dig -f ${SCRIPT_PATH}/dns-exfilteration-nonexistingdomain-queries.txt > /dev/null &

###############################################################################################################

echo "[+] Calling a well known fake domain that is used to generate a known finding"
dig GuardDutyC2ActivityB.com any

###############################################################################################################

echo "[+] Calling bitcoin wallets to download mining toolkits"
curl -s http://pool.minergate.com/dkjdjkjdlsajdkljalsskajdksakjdksajkllalkdjsalkjdsalkjdlkasj -L > /dev/null &
curl -s http://xmr.pool.minergate.com/dhdhjkhdjkhdjkhajkhdjskahhjkhjkahdsjkakjasdhkjahdjk -L > /dev/null &

###############################################################################################################

DECTECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
#declare -a GUARDDUTY_FINDINGS_TYPE=('Backdoor:EC2/DenialOfService.Tcp' 'Backdoor:EC2/C&CActivity.B!DNS' 'Backdoor:EC2/DenialOfService.Dns' 'Stealth:S3/ServerAccessLoggingDisabled' 'PenTest:IAMUser/KaliLinux' 'Policy:Kubernetes/ExposedDashboard' 'Impact:Kubernetes/MaliciousIPCaller' 'Execution:ECS/MaliciousFile' 'DefenseEvasion:Kubernetes/SuccessfulAnonymousAccess' 'UnauthorizedAccess:S3/TorIPCaller' 'UnauthorizedAccess:EC2/TorClient' 'PrivilegeEscalation:Kubernetes/PrivilegedContainer')
declare -a GUARDDUTY_FINDINGS_TYPE=('PenTest:IAMUser/KaliLinux' 'UnauthorizedAccess:S3/TorIPCaller' 'UnauthorizedAccess:EC2/TorClient' 'PrivilegeEscalation:Kubernetes/PrivilegedContainer')

echo "[+] Generate Sample Findings for Alerts"

for ONE_FINDINGS_TYPE in "${GUARDDUTY_FINDINGS_TYPE[@]}"
do
    echo "[+] [Adding Sample] GuardDuty Findings [${ONE_FINDINGS_TYPE}]"
    aws guardduty create-sample-findings --detector-id $DECTECTOR_ID --finding-types ${ONE_FINDINGS_TYPE}
done