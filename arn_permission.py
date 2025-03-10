import boto3
import json

iam_client = boto3.client('iam')

#사용자 ARN에서 attatched, inline policy 모두 가져옴.
def get_attached_policies(user_arn):
    user_name = user_arn.split('/')[-1]

    attached_policies_response = iam_client.list_attached_user_policies(UserName=user_name)#attatched policy 조회
    attached_policies = attached_policies_response.get('AttachedPolicies', [])

    attached_policy_details = []

    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        default_version_id = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id
        )['PolicyVersion']['Document']
    
        attached_policy_info = {
            "PolicyName": policy['PolicyName'],
            "PolicyArn": policy_arn,
            "PolicyDocument": policy_document
        }
        attached_policy_details.append(attached_policy_info)

    inline_policies_response = iam_client.list_user_policies(UserName=user_name)#inline policy 조회
    inline_policy_names = inline_policies_response.get('PolicyNames', [])
    inline_policy_details = []

    for policy_name in inline_policy_names:
        policy_document = iam_client.get_user_policy(
            UserName=user_name,
            PolicyName=policy_name
        )['PolicyDocument']

        inline_policy_info = {
            "PolicyName": policy_name,
            "PolicyDocument": policy_document
        }
        inline_policy_details.append(inline_policy_info)

    return {
        "AttachedPolicies": attached_policy_details,
        "InlinePolicies": inline_policy_details
    }

if __name__ == "__main__":
    example_arn = "your_arn"
    permissions = get_attached_policies(example_arn)

    print(f"Permissions for user {example_arn}:")
    print(json.dumps(permissions, indent=4, ensure_ascii=False))