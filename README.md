# GuardDuty Automation

#### A Mini-Project on GuardDuty & AWS Security Automation

> A Simple GuardDuty Automation Project, which uses Terraform to Setup Guardduty, EventBridge/CloudWatch Events Rule, Lambda Code and Some Test Environment to Trigger Alerts.
The Main Intention of creating this Automation is to learn about GuardDuty and Build Automation around it.


#### How to setup?

<strong>Easy Basic Setup</strong>
1. `git clone` this repo.
2. Provide the Env Variables (as shown below), Without Elastic Stack Dashboard Integration (Use this Recommended)

```
export TF_VAR_ELASTIC_ENROLLMENT_TOKEN=N/A
export TF_VAR_ELASTIC_FLEET_URL=N/A
export TF_VAR_TERRAFORM_STATE_FILE_STATUS=Yes
export TF_VAR_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T04XXXXXXXXXXXXXXXXXXXXXXXXX/XXXXXXXXXXXXX
```

3. Make sure you have exported the AWS Programmatic Keys
my own way is shown below
```
export AWS_ACCESS_KEY_ID=AKIAJDIFLSDJFOPW ; export AWS_SECRET_ACCESS_KEY="uhHJAS/ASDJUASDYQOLAJSDBCALSDJLIWE" ; export AWS_DEFAULT_REGION="us-east-1"
```
4. Run the build.sh file
```
bash build.sh infra-creation 6 No
```


<strong>Advance Setup</strong>
1. `git clone` this repo.
2. Provide the Env Variables (as shown below), With Elastic Stack Dashboard Integration (Advanced) [More Details to be added shortly]

```
export TF_VAR_ELASTIC_ENROLLMENT_TOKEN=bG1pTmVvb0JNSnI4b05IanVjZXU6OG1PS2Z5NFdSMUtGZEp1Qmk2RHY3QQ==
export TF_VAR_ELASTIC_FLEET_URL=https://9fee9f66b65e4906af469989897d4204.fleet.us-central1.gcp.cloud.es.io:443
export TF_VAR_TERRAFORM_STATE_FILE_STATUS=Yes
export TF_VAR_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T04XXXXXXXXXXXXXXXXXXXXXXXXX/XXXXXXXXXXXXX
```

3. Make sure you have exported the AWS Programmatic Keys
my own way is shown below
```
export AWS_ACCESS_KEY_ID=AKIAJDIFLSDJFOPW ; export AWS_SECRET_ACCESS_KEY="uhHJAS/ASDJUASDYQOLAJSDBCALSDJLIWE" ; export AWS_DEFAULT_REGION="us-east-1"
```
4. Run the build.sh file
```
bash build.sh infra-creation 6 No
```


