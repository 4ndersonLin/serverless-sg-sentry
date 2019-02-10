import os
import json
import boto3
from botocore.exceptions import ClientError
import logging

from base64 import b64decode
from urllib2 import Request, urlopen, URLError, HTTPError

ec2_client = boto3.client('ec2')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


slack_channel = os.environ['slack_channel']
slack_hook_url = os.environ['slack_hook_url']



#===============================================================================
def lambda_handler(event, context):

    logger.info('Event:' + str(event))
    # Ensure that we have an event name to evaluate.
    if 'detail' not in event or ('detail' in event and 'eventName' not in event['detail']):
        return {"Result": "Failure", "Message": "Lambda not triggered by an event"}

    # Check for IPv4 and IPv6
    if event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges'] != {}:
        ip_ranges = event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'].encode('utf-8')
    else:
        ip_ranges = event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges']['items'][0]['cidrIpv6'].encode('utf-8')

    rfc_lan_ip = {'10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.'}

    # Bypass the rules that already processed
    if str(event).find('Restrict by Auto-mitigation') != -1 and (ip_ranges.startswith('10.200.200.200') or ip_ranges.startswith('2001:4860:4860::8888')):
        
        logger.info('Not need to process: already processed')
        return {"Result": "Success", "Message": "Not need to process"}

    # Bypass IPv4 lan IP
    elif any([ip_ranges.startswith(ip) for ip in rfc_lan_ip]):
        logger.info('Not need to process: RFC IPv4 Lan')
        return {"Result": "Success", "Message": "RFC Lan not need to process"}

    # Process the ingress rules
    elif event['detail']['eventName'] == 'AuthorizeSecurityGroupIngress':
        result = restrict_security_group_ingress(event['detail'])
        if result == {}:
            message = "Security Group Auto Mitigated:\nAdd multiple rules with the same port.\nDetails: " + json.dumps(event['detail']['requestParameters']['ipPermissions']['items'][0])
        else:
            message = "Security Group Auto Mitigated:\nIngress rule restricted from: {}\nIngress rule added by: {} \nDetails: {}".format(
                    result['group_id'],
                    result['user_name'],
                    json.dumps(event['detail']['requestParameters']['ipPermissions']['items'][0])
                    )

        logger.info('Message: ' + message)
        
        push_slack(message)
        
        # boto3.client('sns').publish(
        #   TargetArn = os.environ['sns_topic_arn'],
        #   Message = message,
        #   Subject = "Auto-mitigation successful"
        #   )

#===============================================================================
# def revoke_security_group_ingress(event_detail):

#     request_parameters = event_detail['requestParameters']

#     # Build the normalized IP permission JSON struture.
#     ip_permissions = normalize_paramter_names(request_parameters['ipPermissions']['items'])

#     response = boto3.client('ec2').revoke_security_group_ingress(
#         GroupId = request_parameters['groupId'],
#         IpPermissions = ip_permissions
#         )


#     # Build the result
#     result = {}
#     result['group_id'] = request_parameters['groupId']
#     result['user_name'] = event_detail['userIdentity']['arn']
#     result['ip_permissions'] = ip_permissions
#     print(result)
#     return result

#===============================================================================
def restrict_security_group_ingress(event_detail):

    request_parameters = event_detail['requestParameters']

    # Build the normalized IP permission JSON struture.
    ip_permissions = normalize_ip_parameter(request_parameters['ipPermissions']['items'])

    response = ec2_client.revoke_security_group_ingress(
        GroupId = request_parameters['groupId'],
        IpPermissions = ip_permissions
        )

    # Encforce to 2001:4860:4860::8888/128 or 10.200.200.200/32 and add description
    ip_permissions = restrict_ip_parameter(request_parameters['ipPermissions']['items'])
    try:
        response = ec2_client.authorize_security_group_ingress(
            GroupId = request_parameters['groupId'],
            IpPermissions = ip_permissions
        )
        # Build the result
        result = {}
        result['group_id'] = request_parameters['groupId']
        result['user_name'] = event_detail['userIdentity']['arn']
        result['ip_permissions'] = ip_permissions
    except ClientError as e:
        result = {}
        logger.error('restrict ingress rule error: ' + str(e))
    logger.info('restrict_security_group_ingress result: ' + str(result))
    
    return result

#===============================================================================
def normalize_ip_parameter(ip_items):

    # Start building the permissions items list.
    new_ip_items = []

    # First, build the basic parameter list.
    for ip_item in ip_items:

        new_ip_item = {
            "IpProtocol": ip_item['ipProtocol'],
            "FromPort": ip_item['fromPort'],
            "ToPort": ip_item['toPort']
        }

        # Check CidrIp or CidrIpv6 (IPv4 or IPv6)
        if 'ipv6Ranges' in ip_item and ip_item['ipv6Ranges']:
            # This is an IPv6 permission range, so change the key names.
            ipv_range_list_name = 'ipv6Ranges'
            ipv_address_value = 'cidrIpv6'
            ipv_range_list_name_capitalized = 'Ipv6Ranges'
            ipv_address_value_capitalized = 'CidrIpv6'
        else:
            ipv_range_list_name = 'ipRanges'
            ipv_address_value = 'cidrIp'
            ipv_range_list_name_capitalized = 'IpRanges'
            ipv_address_value_capitalized = 'CidrIp'

        ip_ranges = []

        # Next, build the IP permission list.
        for item in ip_item[ipv_range_list_name]['items']:
            ip_ranges.append(
                {ipv_address_value_capitalized : item[ipv_address_value]}
                )

        new_ip_item[ipv_range_list_name_capitalized] = ip_ranges

        new_ip_items.append(new_ip_item)

    logger.info('normalize_ip_parameter items: ' + str(new_ip_item))
    
    return new_ip_items

#===============================================================================
def restrict_ip_parameter(ip_items):

    # Start building the permissions items list.
    new_ip_items = []

    # First, build the basic parameter list.
    for ip_item in ip_items:

        new_ip_item = {
            "IpProtocol": ip_item['ipProtocol'],
            "FromPort": ip_item['fromPort'],
            "ToPort": ip_item['toPort']
        }

        # Check CidrIp or CidrIpv6 (IPv4 or IPv6)
        if 'ipv6Ranges' in ip_item and ip_item['ipv6Ranges']:
            ipv_range_list_name = 'ipv6Ranges'
            ipv_address_value = 'cidrIpv6'
            ipv_range_list_name_capitalized = 'Ipv6Ranges'
            ipv_address_value_capitalized = 'CidrIpv6'
            ip_ranges = [{'CidrIpv6': '2001:4860:4860::8888/128','Description': 'Restrict by Auto-mitigation'}]

        else:
            ipv_range_list_name = 'ipRanges'
            ipv_address_value = 'cidrIp'
            ipv_range_list_name_capitalized = 'IpRanges'
            ipv_address_value_capitalized = 'CidrIp'
            ip_ranges = [{'CidrIp': '10.200.200.200/32','Description': 'Restrict by Auto-mitigation'}]


        new_ip_item[ipv_range_list_name_capitalized] = ip_ranges

        new_ip_items.append(new_ip_item)
    
    logger.info('restrict_ip_parameter items: ' + str(new_ip_item))
    
    return new_ip_items

#===============================================================================
def push_slack(msg):
    slack_message = {
        'channel': slack_channel,
        'text': msg
        }

    req = Request(slack_hook_url, json.dumps(slack_message))
    
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)