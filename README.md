# Serverless Security Group Sentry
If one of your staff members (inadvertently | mischievously) modifies your VPC security group to allow SSH access to the world,
you want the change to be automatically reverted and then receive a notification that the change to the security group was automatically reverted.

## Automatically Revert and Receive Notifications About Changes to Your Amazon VPC Security Groups

Here is how the process works,
1. Someone adds a new `ingress` rule to any security group
1. A CloudWatch event that continually monitors changes to your security groups detects the new ingress rule and invokes Lambda function
1. Lambda function determines whether you are monitoring this security group
   1. Reverts the new security group ingress rule.
   1. _**Optionally**_: Sends you an SNS Notification email to let you know what the change was, who made it, and that the change was reverted


## Pre-Requisities
We will need the following pre-requisites to successfully complete this activity,
- `AWS CloudTrail` must be enabled in the AWS Region where the solution is deployed
- IAM Role - _i.e_ `Lambda Service Role` - _with_ `EC2FullAccess` _permissions_
  - _You may use an `Inline` policy with more restrictive permissions_

_The image above shows the execution order, that should not be confused with the numbering of steps given here_

## Step 1 - Configure Lambda Function- `SG-Sentry-Bot`
The below script is written in `Python 2.7`. Remember to choose the same in AWS Lambda Functions.

_Change the global variables at the top of the script to suit your needs._

```
Environment variables:
...
slack_channel = os.environ['slack_channel']
slack_hook_url = os.environ['slack_hook_url']
...
```
After pasting the code, Scroll down to create a environment variable Key as `security_group_id` and Value as the `Security Group ID` that we need to monitor. `Save` the lambda function

## Step 2 - Configure Lambda Triggers
We are going to use Cloudwatch Events that will be triggered by `CloudTrail API`
1. Choose `Create a new Rule`
1. Fill the `Rule Name` & `Rule Description`
1. For `Rule Type` - Choose `Event pattern`
   1. Below that, Choose `EC2` Service
   1. In the next field, Choose `AWS API call via CloudTrail`
1. Check the `Operation` box,
   1. In below field, Type/Choose both `AuthorizeSecurityGroupIngress` & `AuthorizeSecurityGroupEgress`
1. `Enable` Trigger by `Checking` the box
1. Click on `Add` and `Save` the Lambda Function

## Step 3 - Testing the solution
Navigate to the `EC2 console` and choose `Security Groups` and Choose the security group that we are monitoring.
Add a new `Inbound` rule, for example `SSH` on port `22` from `0.0.0.0/0`.

Adding this rule creates an **EC2** `AuthorizeSecurityGroupIngress` service event, which triggers the Lambda function.

After a few moments, choose the refresh button ( The "**refresh**" icon ) to see that the new _ingress_ rule that you just created has been retrict to the specific IP(IPv6 is google DNS) by the solution.

### Summary
Restrict/revert security change and add description for it then send notification to Slack.