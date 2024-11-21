# monthly-aws-account-running-resources-scanner
# Overview
This project is aimed automating the scanning of an AWS account to identify running services, retrieve their details, and generate a report. The report is then emailed to a specified address using Amazon SES. Additionally, it can terminate identified resources if required. This is particularly useful for monitoring resource usage and controlling costs in an AWS environment.

# Features
List Running AWS Services: Scans for EC2, RDS, S3, OpenSearch, Kendra, DynamoDB, Lambda, CloudWatch Alarms, ELB, Redshift, Step Functions, and App Runner services.
Generate CSV Report: Collects information about the service, resource ID, creation date, IAM user, and region, and writes it to a CSV file.
Email Report: Uses Amazon SES to send the generated report via email.
Optional Termination: Includes functionality to terminate the identified resources.

# Requirements
AWS account with appropriate permissions including ALL necessary policies for the lambda to assume the role of each service involved.
Boto3 library installed.
Python 3.7+ runtime for the Lambda function or local execution with runtime configured to 10 minutes.
Amazon SES setup with a verified sender email address.

# Setup
# 1. Create and Configure AWS Lambda Function
Create a Lambda function with the Python 3.7+ runtime.
Attach an execution role with the necessary IAM permissions.

# 2. Update IAM Permissions
Ensure the Lambda execution role includes the necessary permissions as below:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeRegions",
                "ec2:DescribeInstances",
                "rds:DescribeDBInstances",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "es:ListDomainNames",
                "es:DescribeElasticsearchDomain",
                "kendra:ListIndices",
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "lambda:ListFunctions",
                "cloudwatch:DescribeAlarms",
                "elasticloadbalancing:DescribeLoadBalancers",
                "redshift:DescribeClusters",
                "states:ListStateMachines",
                "apprunner:ListServices"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:TerminateInstances",
                "rds:DeleteDBInstance",
                "s3:DeleteBucket",
                "es:DeleteElasticsearchDomain",
                "kendra:DeleteIndex",
                "dynamodb:DeleteTable",
                "lambda:DeleteFunction",
                "cloudwatch:DeleteAlarms",
                "elasticloadbalancing:DeleteLoadBalancer",
                "redshift:DeleteCluster",
                "states:DeleteStateMachine",
                "apprunner:DeleteService"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "ses:SendRawEmail",
            "Resource": "*"
        }
    ]
}

# 3. Create and Verify SES Identity
Verify the sender email address in Amazon SES.

# 4. Define the CRON Expression
Use a CRON expression to schedule the Lambda function to run on the first of every month:
cron(0 0 1 * ? *)

# 5. Package and Deploy the Code
Package the code and dependencies into a ZIP file into a separate Python3 environment.
Upload the ZIP file to the AWS Lambda console.

# Python Script
# Ensure the following script is used for the Lambda function:
import boto3
from datetime import datetime, timezone
import csv
import os
from botocore.exceptions import ClientError, EndpointConnectionError
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def get_enabled_regions():
    ec2 = boto3.client('ec2')
    regions = ec2.describe_regions()['Regions']
    return [region['RegionName'] for region in regions]

def is_service_available(service, region):
    client = boto3.client(service, region_name=region)
    try:
        if service == 's3':
            return True  # S3 is a global service, no need to check region-specific availability
        else:
            if service == 'ec2':
                client.describe_instances()
            elif service == 'rds':
                client.describe_db_instances()
            # elif service == 's3':
            #     client.list_buckets()
            elif service == 'es':
                client.list_domain_names()
            elif service == 'kendra':
                client.list_indices()
            elif service == 'dynamodb':
                client.list_tables()
            elif service == 'lambda':
                client.list_functions()
            elif service == 'redshift': 
                client.describe_clusters() 
            elif service == 'stepfunctions':
                client.list_state_machines()
            # elif service == 'apprunner':
            #     client.list_services()
            elif service == 'cloudwatch':
                client.describe_alarms()
            elif service == 'elb':
                client.describe_load_balancers()
            return True
    except (ClientError, EndpointConnectionError):
        return False

def scan_aws_resources(writer):
    services = ['ec2', 'rds', 's3', 'es', 'kendra', 'dynamodb', 'lambda', 'redshift', 'stepfunctions', 'cloudwatch', 'elb']  # Add other services as needed
    regions = get_enabled_regions()  # Get all regions

    empty_report = {}

    #Handle S3 buckets separately since they are global
    if services == 's3':
        try:
            s3_client = boto3.client('s3')
            buckets = client.list_buckets()
            for bucket in buckets['Buckets']:
                resource_id = bucket['Name']
                creation_date = bucket['CreationDate']
                iam_user = 'Unknown'  # S3 does not directly provide IAM user info
                empty_report["Service"] = service
                empty_report["Resource_Id"] = resource_id
                empty_report["Creation_Date"] = creation_date
                empty_report["IAM_User"] = iam_user
                empty_report["Region"] = 'global' #S3 is a global resource
                writer.writerow(empty_report)
        except ClientError as e:
            print(f"Error retrieving S3 Buckets: {e}")

    for region in regions:
        for service in services:
            if not is_service_available(service, region):
                print(f"Skipping service {service} in region {region}: Not available or not authorized")
                continue
            client = boto3.client(service, region_name=region)
            try:
                # Scan EC2 instances
                if service == 'ec2':
                    instances = client.describe_instances()
                    for reservation in instances['Reservations']:
                        for instance in reservation['Instances']:
                            resource_id = instance['InstanceId']
                            creation_date = instance['LaunchTime']
                            iam_user = instance.get('KeyName', 'Unknown')
                            # Collect information about the resource
                            empty_report["Service"] = service
                            empty_report["Resource_Id"] = resource_id
                            empty_report["Creation_Date"] = creation_date
                            empty_report["IAM_User"] = iam_user
                            empty_report["Region"] = region
                            writer.writerow(empty_report)

                # Scan RDS instances
                elif service == 'rds':
                    instances = client.describe_db_instances()
                    for instance in instances['DBInstances']:
                        resource_id = instance['DBInstanceIdentifier']
                        creation_date = instance['InstanceCreateTime']
                        iam_user = instance.get('MasterUsername', 'Unknown')
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                # Scan OpenSearch (formerly Elasticsearch) domains
                elif service == 'es':
                    domains = client.list_domain_names()
                    for domain in domains['DomainNames']:
                        domain_info = client.describe_elasticsearch_domain(DomainName=domain['DomainName'])
                        resource_id = domain_info['DomainStatus']['DomainId']
                        creation_date = domain_info['DomainStatus']['Created']
                        iam_user = 'Unknown'  # OpenSearch does not directly provide IAM user info
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                # Scan Kendra indices
                elif service == 'kendra':
                    indexes = client.list_indices()
                    for index in indexes['IndexConfigurationSummaryItems']:
                        resource_id = index['Id']
                        creation_date = index['CreatedAt']
                        iam_user = 'Unknown'  # Kendra does not directly provide IAM user info
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                # Scan DynamoDB tables
                elif service =='dynamodb':
                    tables = client.list_tables()
                    for table_name in tables['TableNames']:
                        table_info = client.describe_table(TableName=table_name)
                        resource_id = table_info['Table']['TableId']
                        creation_date = table_info['Table']['CreationDateTime']
                        iam_user = 'Unknown' # DynamoDB does not directly provide IAM user info
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                # Scan Lambda functions
                elif service == 'lambda':
                    functions = client.list_functions()
                    for function in functions['Functions']:
                        resource_id = function['FunctionName']
                        creation_date = function['LastModified']
                        iam_user = function.get('Role', 'Unknown')
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                #Scan Redshift Clusters
                elif service =='redshift':
                    clusters = client.describe_clusters()
                    for cluster in clusters['Clusters']:
                        resource_id = cluster['ClusterIdentifier']
                        creation_date = cluster['ClusterCreationTime']
                        iam_user = cluster.get(['MasterUsername', 'Unknown'])
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                #Scan Step Functions
                elif service == 'stepfunctions':
                    state_machines = client.list_state_machines()
                    for state_machine in state_machines['stateMachines']:
                        resource_id = state_machine['stateMachineArn']
                        creation_date = state_machine['creation_date']
                        iam_user = 'Unknown' # Step Functions does not directly provide IAM user info
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                # elif service == 'apprunner':
                #     services = client.list_services()
                #     for service_info in services['ServiceSummaryList']:
                #         resource_id = service_info['ServiceId']
                #         creation_date = service_info['CreatedAt']
                #         iam_user = 'Unknown' #App Runner does not directly provide IAM user info 
                #         empty_report["Service"] = service
                #         empty_report["Resource_Id"] = resource_id
                #         empty_report["Creation_Date"] = creation_date
                #         empty_report["IAM_User"] = iam_user
                #         empty_report["Region"] = region
                #         writer.writerow(empty_report)

                #Scan Cloudwatch Alarms
                elif service == 'cloudwatch':
                    alarms = client.describe_alarms()
                    for alarm in alarms['MetricAlarms']:
                        resource_id = alarm['AlarmName']
                        creation_date = alarm['AlarmConfigurationUpdatedTimestamp']
                        iam_user = 'Unknown' #CloudWatch does not directly provide IAM user info
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                #Scan Elastic Load Balancers
                elif service == 'elb':
                    elbs = client.describe_load_balancers()
                    for elb in elbs['LoadBalancerDescriptions']:
                        resource_id = elb['LoadBalancerName']
                        creation_date = elb['CreatedTime']
                        iam_user = 'Unknown' # ELB does not directly provide IAM user info
                        empty_report["Service"] = service
                        empty_report["Resource_Id"] = resource_id
                        empty_report["Creation_Date"] = creation_date
                        empty_report["IAM_User"] = iam_user
                        empty_report["Region"] = region
                        writer.writerow(empty_report)

                # Add other services as needed

            except ClientError as e:
                print(f"Error retrieving {service} in region {region}: {e}")

def send_report_to_emails(file_name):
    SENDER = "emmanueljunior9@yahoo.com"
    RECIPIENT = "emmanueljunior9@yahoo.com"
    SUBJECT = "AWS Resources Report"
    ATTACHMENT = file_name
    BODY_HTML = """
    <html>
    <head></head>
    <body>
    <h1>AWS Resources Report</h1>
    <p>Attached is the monthly report of MOST running AWS resources which need to be terminated IMMEDIATELY!!!.</p>
    </body>
    </html>
    """
    CHARSET = "utf-8"
    client = boto3.client('ses', region_name="us-west-2")
    msg = MIMEMultipart('mixed')
    msg['Subject'] = SUBJECT
    msg['From'] = SENDER
    msg['To'] = RECIPIENT

    msg_body = MIMEMultipart('alternative')
    htmlpart = MIMEText(BODY_HTML.encode(CHARSET), 'html', CHARSET)
    msg_body.attach(htmlpart)

    att = MIMEApplication(open(ATTACHMENT, 'rb').read())
    att.add_header('Content-Disposition', 'attachment', filename=os.path.basename(ATTACHMENT))

    msg.attach(msg_body)
    msg.attach(att)

    try:
        response = client.send_raw_email(
            Source=SENDER,
            Destinations=[RECIPIENT],
            RawMessage={'Data': msg.as_string()}
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent successfully! with Message ID:", response['MessageId'])

def terminate_resource(service, resource_id, region):
    client = boto3.client(service, region_name=region)
    try:
        if service == 'ec2':
            client.terminate_instances(InstanceIds=[resource_id])
        elif service == 'rds':
            client.delete_db_instance(DBInstanceIdentifier=resource_id, SkipFinalSnapshot=True)
        elif service == 's3':
            client.delete_bucket(Bucket=resource_id)
        elif service == 'es':
            client.delete_elasticsearch_domain(DomainName=resource_id)
        elif service == 'kendra':
            client.delete_index(Id=resource_id)
        elif service == 'dynamodb': 
            client.delete_table(TableName=resource_id) 
        elif service == 'lambda': 
            client.delete_function(FunctionName=resource_id) 
        elif service == 'redshift': 
            client.delete_cluster(ClusterIdentifier=resource_id, SkipFinalSnapshot=True) 
        elif service == 'stepfunctions': 
            client.delete_state_machine(stateMachineArn=resource_id) 
        # elif service == 'apprunner':
        #   client.delete_service(ServiceArn=resource_id)
        elif service == 'cloudwatch': 
            client.delete_alarms(AlarmNames=[resource_id]) 
        elif service == 'elb': 
            client.delete_load_balancer(LoadBalancerName=resource_id)
        print(f"Terminated {service} resource: {resource_id}")
    except ClientError as e:
        print(f"Error terminating {service} resource {resource_id}: {e}")

def lambda_handler(event, context):
    field_names = ["Service", "Resource_Id", "Creation_Date", "IAM_User", "Region"]
    file_name = "/tmp/AWS_Resources_Report.csv"
    with open(file_name, "w", newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()
        scan_aws_resources(writer)
    send_report_to_emails(file_name)

    # Uncomment to terminate resources
    # terminate_resource('ec2', 'instance_id', 'region')

# Running the Function
Once deployed, the Lambda function will automatically run on the first of every month, as scheduled by the CRON job through a cloudwatch events trigger. The function scans the AWS account for resources, generates a report, and sends it via email.

# Error Handling and Logging
# Common Errors
Access Denied: Ensure the IAM role has the necessary permissions.
Service Unavailable: Verify that the service is available in the specified region.
Endpoint Connection Error: Confirm network connectivity and that the service is supported in the region.
Sandbox time out: Recheck the runtime in the configurations tab and set it to atleast 8 minutes

# Troubleshooting
Check the Lambda function logs in CloudWatch for detailed error messages.
Verify that all required services and regions are supported and enabled in your AWS account.

# Contributing
Contributions are welcome! Please feel free to submit issues and pull requests.

License
This project is licensed under the MIT License. See the LICENSE file for more details.
