#!/bin/bash

TERRAFORM_CODE_DIR=${1?Error: Provide Path where Terraform Code (.tf) is kept}
TIME_TO_SLEEP=${2?Error: Provide Time to Sleep(In Seconds) Before Terrform Apply as 1st Arg}
REMOVE_OLD_TFSTATE=${3?Error: Are You Running it in New Account or Want a Fresh Setup, Provide [Yes] to remove old Terraform State files}

echo "ENV Variables Provided are:"
echo "TF VAR ELASTIC_ENROLLMENT_TOKEN: [$TF_VAR_ELASTIC_ENROLLMENT_TOKEN]"
echo "TF VAR ELASTIC_FLEET_URL: [$TF_VAR_ELASTIC_FLEET_URL]"
echo "TF VAR SLACK_WEBHOOK_URL: [$TF_VAR_SLACK_WEBHOOK_URL]"
echo "TF VAR TERRAFORM_STATE_FILE_STATUS: [$TF_VAR_TERRAFORM_STATE_FILE_STATUS]"

echo "------------------"
echo "[Moving Inside: $TERRAFORM_CODE_DIR]: Listing Files"
cd $TERRAFORM_CODE_DIR
pwd; ls -al
echo "------------------"

if [[ "${REMOVE_OLD_TFSTATE}" == "Yes" ]];
then
    echo "[Removing OLD TFSTATE]";
    rm -rfv terraform.tfstate*
else
    echo "[Do Not Delete OLD TFSTATE]"
fi

echo "------------------"
echo "AWS Account, Role Details"
aws sts get-caller-identity
echo "------------------"

echo "[Start] Terraform Apply with AutoApprove in ${TIME_TO_SLEEP} Seconds"
sleep ${TIME_TO_SLEEP}s

echo "[Starting] Terraform Apply with AutoApprove...."
terraform apply --auto-approve