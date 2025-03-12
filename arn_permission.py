import boto3
import json

iam_client = boto3.client('iam')

def get_user_permissions(user_arn):
    user_name = user_arn.split('/')[-1]
    permissions = set()
    
    # Attached Policies
    attached_policies_response = iam_client.list_attached_user_policies(UserName=user_name)
    attached_policies = attached_policies_response.get('AttachedPolicies', [])
    
    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        default_version_id = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id
        )['PolicyVersion']['Document']
        
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):  # 단일 Statement 처리
            statements = [statements]
        
        for statement in statements:
            if 'Action' in statement:
                actions = statement['Action']
                if isinstance(actions, str):
                    permissions.add(actions)
                else:
                    permissions.update(actions)
    
    # Inline Policies
    inline_policies_response = iam_client.list_user_policies(UserName=user_name)
    inline_policy_names = inline_policies_response.get('PolicyNames', [])
    
    for policy_name in inline_policy_names:
        policy_document = iam_client.get_user_policy(
            UserName=user_name,
            PolicyName=policy_name
        )['PolicyDocument']
        
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):  # 단일 Statement 처리
            statements = [statements]
        
        for statement in statements:
            if 'Action' in statement:
                actions = statement['Action']
                if isinstance(actions, str):
                    permissions.add(actions)
                else:
                    permissions.update(actions)
    
    return list(permissions)

if __name__ == "__main__":
    example_arn = "arn:aws:iam::863518424796:user/kimtest"
    user_permissions = get_user_permissions(example_arn)
    
    print(f"Permissions for user {example_arn}:")
    print(json.dumps(user_permissions, indent=4, ensure_ascii=False))