import json
import os
import urllib.request
from urllib.error import URLError, HTTPError
from dateutil import parser

## Webhook URL // Added in Lambda Environment Vairables
SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]

## Convert JSON to Flatten JSON... [Level 1]
def flat_it(json_obj):
    new_dict = {}
    for f,v in json_obj.items():
        if type(v) is dict:
            for f1,v1 in v.items():
                f = f[0].title() + f[1:]
                f1 = f1[0].title() + f1[1:]
                new_dict[f + "-" + f1] = v1
        else:
            f = f[0].title() + f[1:]
            new_dict[f] = v
    return new_dict


## Build the Message to SLACK Format
def build_message(msgtitle, msgsubtitle,details_list):
    return {
        "text": msgtitle,
        "username": "GuardDuty Alert",
        "icon_url": "https://raw.githubusercontent.com/aashishrbhandari/web_resources/main/img/aws/guardduty/logo/guarduty_logo_01.png",
        "attachments": [
            {
                "pretext": msgsubtitle,
                "color": "#FF0000",
                "fields": details_list
            }
        ]
    }


## Build the Message to SLACK Format [SHORTINFO]
def build_message_shortinfo(preview_pretext, title, title_link, description_text, details_list, action_list):
    return {
        "channel": "#guardduty-alerts",
        "text": "",
        "username": "GuardDuty Alert",
        "icon_url": "https://raw.githubusercontent.com/aashishrbhandari/web_resources/main/img/aws/guardduty/logo/guarduty_logo_01.png",
        "attachments": [
            {
                "pretext": preview_pretext,
                "title": title,
                "title_link": title_link,
                "text": description_text,
                "color": "#FF0000",
                "fields": details_list,
                "mrkdwn_in": [
                    "pretext",
                    "title"
                ],
                "actions": action_list
            }
        ],
    }


## Identify if the given string is Python Dictionary
def is_dict(str_value):
    if type(str_value) is int:
        return False
    if type(str_value) is dict:
        return True
    else:
        return False


## Convert Date to Local Time Stamp - Slack Specific
def convert_to_local_time_slack_format(datetime_str):
    epoch_time = int(parser.parse(datetime_str).timestamp())
    return f'<!date^{epoch_time}^ {{date}} at {{time}} | {datetime_str}>'


## Check for Dict Value and Return Empty if KeyError
def get_nested_key_value(thedict, key_list):
    try:
        newdict = thedict.copy()
        for one_key in key_list:
            newdict = newdict[one_key]
        return newdict
    except KeyError:
        return ".".join(key_list)


## Converting Events JSON to Slack Format
def convert_to_alert(event_detail):

    exclude_fields = [
        "SchemaVersion",
        "Partition",
        "Id",
        "Arn",
        "Service-ServiceName",
        "Service-DetectorId"
    ]

    event_title =  get_nested_key_value(event_detail, ["title"])
    event_type =  get_nested_key_value(event_detail, ["type"])
    event_severity = get_nested_key_value(event_detail, ["severity"])

    event_resourcetype = get_nested_key_value(event_detail, ["resource", "resourceType"])
    event_actiontype = get_nested_key_value(event_detail, ["service", "action", "actionType"])
    event_count = get_nested_key_value(event_detail, ["service", "count"])

    subject = f":loudspeaker: *GuardDuty | {event_type} | Severity - {event_severity}* "
    subject_summary = f"> *{event_title} | {event_resourcetype} | {event_actiontype} | Count - {event_count}*"

    detail_dict = flat_it(event_detail)

    print(detail_dict)

    details_list = []

    for one_detail in detail_dict:
        
        event_name = one_detail
        event_details = detail_dict[one_detail]
        
        if event_name not in exclude_fields:
        
            if is_dict(event_details):
                event_details = json.dumps(detail_dict[one_detail], indent = 2)
                details_list.append(
                    {  
                        "title": f"{event_name}",  
                        "value": f"```{event_details}```",
                        "short": False
                    }
                )
                
            else:
                event_details = str(detail_dict[one_detail])
                details_list.append(
                    {  
                        "title": f"{event_name}",  
                        "value": f"{event_details}",
                        "short": len(event_details) < 50
                    }
                )
    
    return build_message(subject, subject_summary, details_list)


## Converting Events JSON to Slack Format
def convert_to_alert_shortinfo(event_detail):

    event_region = get_nested_key_value(event_detail, ["region"])
    event_accountId = get_nested_key_value(event_detail, ["accountId"])
    event_severity = get_nested_key_value(event_detail, ["severity"])

    event_id = get_nested_key_value(event_detail, ["id"])
    event_description =  get_nested_key_value(event_detail, ["description"])
    
    event_type =  get_nested_key_value(event_detail, ["type"])

    preview_pretext = f"*Severity: {event_severity} found in {event_region} for {event_accountId}*"
    title = f"{event_type}"
    description_text = f"*{event_description}*"
    title_link = f'https://console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?search=id%3D{event_id}'

    guardduty_event_filter = f'https://console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?macros=current&fId={event_id}'
    guardduty_findings_page = 'https://console.aws.amazon.com/guardduty/home?region=us-east-1#/findings'

    action_list = [
        {
            "type": "button",
            "name": "Check GuardDuty Event",
            "text": "Check GuardDuty Event",
            "url": guardduty_event_filter,
            "style": "primary"
        },
        {
            "type": "button",
            "name": "GuardDuty Findings Page",
            "text": "GuardDuty Findings Page",
            "url": guardduty_findings_page,
            "style": "danger"
        }
    ]

    detail_dict = flat_it(event_detail)

    print(detail_dict)

    details_list = []

    include_fields = [
        "Service-EventFirstSeen",
        "Service-EventLastSeen",
        "Resource-ResourceType",
        "Service-ResourceRole",
        "Service-Count",
        "Severity",
        "Region",
        "UpdatedAt",
        "AccountId"
    ]

    date_fields = [
        "Service-EventFirstSeen",
        "Service-EventLastSeen",
        "UpdatedAt"
    ]

    details_list.append(
        {  
            "title": "",  
            "value": "",
            "short": False
        }
    )

    for one_detail in detail_dict:
        
        event_name = one_detail
        event_details = detail_dict[one_detail]
        
        if event_name in include_fields:
        
            if is_dict(event_details):
                event_details = json.dumps(detail_dict[one_detail], indent = 2)
                details_list.append(
                    {  
                        "title": f"{event_name}",  
                        "value": f"```{event_details}```",
                        "short": False
                    }
                )
            else:
                event_details = str(detail_dict[one_detail])
                if event_name in date_fields:
                    details_list.append(
                        {  
                            "title": f"{event_name}",  
                            "value": f"{convert_to_local_time_slack_format(event_details)}",
                            "short": len(event_details) < 50
                        }
                    )
                else:
                    details_list.append(
                        {  
                            "title": f"{event_name}",  
                            "value": f"{event_details}",
                            "short": len(event_details) < 50
                        }
                    )
    
    return build_message_shortinfo(preview_pretext, title, title_link, description_text, details_list, action_list)


## Main Function for Lambda -- Which Recevies Event JSON from EventBridge
def lambda_handler(event, context):
    try:
        event_detail = event["detail"]
        msg = convert_to_alert_shortinfo(event_detail)
        response = urllib.request.urlopen(urllib.request.Request(SLACK_WEBHOOK_URL, json.dumps(msg).encode('utf-8')))
        response.read()
    except HTTPError as http_error:
        print(f"Request to [Slack Webhook] --- failed: {http_error.code} {http_error.reason}")
    except URLError as url_error:
        print(f"Server connection to [Slack Webhook] --- failed: {url_error.reason}")

    return "Completed"