import boto3
import json
import time
import random
iam = boto3.client('iam')
account_id = boto3.client('sts').get_caller_identity()['Account']

# Trust policy allowing the account itself to assume the role
trust_policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "sts:AssumeRole"
    }]
}

# 활동 함수별 권한 매핑
activity_permissions = {
    "ec2_activity": ["ec2:DescribeInstances"],
    "iam_activity": ["iam:ListUsers", "iam:ListRoles", "iam:ListPolicies"],
    "s3_activity": ["s3:ListAllMyBuckets", "s3:ListBucket", "s3:ListObjectsV2",],
    "lambda_activity": ["lambda:ListFunctions"],
    "cloudwatch_activity": ["cloudwatch:DescribeAlarms", "cloudwatch:ListMetrics"],
    "cloudtrail_activity": ["cloudtrail:DescribeTrails"],
    "dynamodb_activity": ["dynamodb:ListTables"],
    "sns_activity": ["sns:ListTopics"],
    "sts_activity": ["sts:GetCallerIdentity"],
    "rds_activity": ["rds:DescribeDBInstances"],
    "s3_create_delete_activity": ["s3:CreateBucket", "s3:DeleteBucket"],
    "iam_privilege_escalation_attempt": ["iam:AttachUserPolicy"],
    "invalid_s3_access": ["s3:ListObjectsV2"],
    "ec2_key_pair_activity": ["ec2:CreateKeyPair", "ec2:DeleteKeyPair"],
    "ecr_repository_activity": ["ecr:CreateRepository", "ecr:DeleteRepository"],
    "cloudwatch_log_group_activity": ["logs:CreateLogGroup", "logs:DeleteLogGroup"],
    "s3_public_access_attempt": ["s3:PutBucketPublicAccessBlock", "s3:CreateBucket", "s3:DeleteBucket"],
    "iam_access_key_activity": ["iam:CreateAccessKey"]
}

all_permissions = []
for perms in activity_permissions.values():
    all_permissions.extend(perms)
all_permissions = sorted(set(all_permissions))  # 총 17개 예상
for i in range(1, 21):
    role_name = f"ML_dataset_role{i}"
    print(f"\n▶ Creating role: {role_name}")

    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Simulated role {role_name} for CloudTrail log generation"
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"⚠️ Role {role_name} already exists. Skipping create.")

    # 각 역할별로 고유한 하나의 permission만 누락
    excluded_index = (i - 1) % len(all_permissions)
    excluded_permission = all_permissions[excluded_index]
    final_permissions = [p for p in all_permissions if p != excluded_permission]

    print(f"⛔ {role_name} will exclude permission: {excluded_permission}")

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": final_permissions,
            "Resource": "*"
        }]
    }

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{role_name}_inline_policy",
        PolicyDocument=json.dumps(policy)
    )

    print(f"✅ {role_name}: {len(final_permissions)} permissions assigned.")
    time.sleep(1)