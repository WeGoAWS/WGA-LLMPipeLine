import boto3
import random
import string
import time
from botocore.config import Config

# User-Agent 설정
user_agents_normal = [
    'Boto3/1.28.0 Python/3.10 Linux/5.4.0',
    'aws-cli/2.11.0 Python/3.9 Windows/10 botocore/2.0.0',
    'aws-sdk-java/1.12.0 Linux OpenJDK',
    'aws-sdk-go/1.44.85 (go1.20; linux; amd64)'
]
user_agents_anomalous = [
    'curl/7.78.0',
    'CustomScanner/1.0',
    'sqlmap/1.5',
    'python-requests/2.26.0'
]

# 리전 및 Role 목록
regions = ['ap-northeast-2', 'us-east-1', 'ap-northeast-1', 'us-west-2', 'eu-west-1']
ROLE_ARNS = [f"arn:aws:iam::863518424796:role/ML_dataset_role{i}" for i in range(1, 21)]

# 랜덤 이름 생성
def random_name(prefix='resource', length=8):
    return f"{prefix}-" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# 클라이언트 생성 함수
def get_client(service, region, role_arn):
    if random.random() < 0.005:
        user_agent = random.choice(user_agents_anomalous)
    else:
        user_agent = random.choice(user_agents_normal)

    config = Config(user_agent=user_agent, region_name=region)
    sts = boto3.client('sts')
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=random_name('session'))['Credentials']

    return boto3.client(
        service,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        config=config
    )

# 액티비티 정의
def ec2_activity(region, client): client.describe_instances()
def iam_activity(region, client): client.list_users(); client.list_roles(); client.list_policies(Scope='Local')
def s3_activity(region, client): [client.list_objects_v2(Bucket=b['Name'], MaxKeys=5) for b in client.list_buckets().get('Buckets', [])]
def lambda_activity(region, client): client.list_functions()
def cloudwatch_activity(region, client): client.describe_alarms(); client.list_metrics(Namespace='AWS/EC2')
def cloudtrail_activity(region, client): client.describe_trails()
def dynamodb_activity(region, client): client.list_tables()
def sns_activity(region, client): client.list_topics()
def sts_activity(region, client): client.get_caller_identity()
def rds_activity(region, client): client.describe_db_instances()
def s3_create_delete_activity(region, client):
    name = random_name('bucket')
    if region == 'us-east-1':
        client.create_bucket(Bucket=name)
    else:
        client.create_bucket(Bucket=name, CreateBucketConfiguration={'LocationConstraint': region})
    time.sleep(1)
    client.delete_bucket(Bucket=name)
def ec2_key_pair_activity(region, client):
    name = random_name('key')
    client.create_key_pair(KeyName=name)
    client.delete_key_pair(KeyName=name)
def s3_public_access_attempt(region, client):
    name = random_name('bucket')
    if region == 'us-east-1':
        client.create_bucket(Bucket=name)
    else:
        client.create_bucket(Bucket=name, CreateBucketConfiguration={'LocationConstraint': region})
    client.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': False,
            'IgnorePublicAcls': False,
            'BlockPublicPolicy': False,
            'RestrictPublicBuckets': False
        }
    )
    client.delete_bucket(Bucket=name)

# 비정상 활동
def invalid_s3_access(region, client): client.list_objects_v2(Bucket='non-existent-bucket-xyz123')
def iam_privilege_escalation_attempt(region, client): client.attach_user_policy(UserName='someuser', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')

# 파라미터 오류 유도
def invalid_param_activity(region, client):
    error_actions = [
        lambda: client.list_objects_v2(Bucket='definitely-not-real-bucket-xyz'),
        lambda: client.describe_instances(Filters=[{}]),
        lambda: client.describe_security_groups(GroupIds=['sg-00000000']),
        lambda: client.describe_db_instances(DBInstanceIdentifier='not-a-db'),
        lambda: client.get_user(UserName='no-such-user'),
        lambda: client.describe_repositories(repositoryNames=['fake-repo'])
    ]
    try:
        random.choice(error_actions)()
    except Exception as e:
        raise e

# 액티비티 그룹
normal_actions = [
    ec2_activity, iam_activity, s3_activity, lambda_activity,
    cloudwatch_activity, cloudtrail_activity, dynamodb_activity,
    sns_activity, sts_activity, rds_activity,
    s3_create_delete_activity, ec2_key_pair_activity,
    s3_public_access_attempt
]

abnormal_actions = [
    invalid_s3_access, iam_privilege_escalation_attempt
]

# 서비스 이름 매핑
activity_service_map = {
    ec2_activity: 'ec2',
    iam_activity: 'iam',
    s3_activity: 's3',
    lambda_activity: 'lambda',
    cloudwatch_activity: 'cloudwatch',
    cloudtrail_activity: 'cloudtrail',
    dynamodb_activity: 'dynamodb',
    sns_activity: 'sns',
    sts_activity: 'sts',
    rds_activity: 'rds',
    s3_create_delete_activity: 's3',
    ec2_key_pair_activity: 'ec2',
    s3_public_access_attempt: 's3',
    iam_privilege_escalation_attempt: 'iam',
    invalid_s3_access: 's3',
    invalid_param_activity: 'ec2'
}

# 메인 실행 루프
iteration = 0
while True:
    iteration += 1
    region = random.choice(regions)
    role_arn = random.choice(ROLE_ARNS)
    role_name = role_arn.split('/')[-1]

    log_type = random.choices(["normal", "invalid_param"], weights=[0.85, 0.15], k=1)[0]

    if log_type == "normal":
        num_total = random.randint(6, 12)
        num_abnormal = int(num_total * random.uniform(0.05, 0.1))
        num_normal = num_total - num_abnormal

        selected_activities = (
            random.sample(normal_actions, k=num_normal) +
            random.sample(abnormal_actions, k=min(num_abnormal, len(abnormal_actions)))
        )
        random.shuffle(selected_activities)

        for activity in selected_activities:
            service_name = activity_service_map[activity]
            client = get_client(service_name, region, role_arn)

            try:
                activity(region, client)
                print(f"🟩 정상 - {role_name} - {activity.__name__} 성공")
            except Exception as e:
                print(f"🟩 정상 - {role_name} - {activity.__name__} 오류: {e}")

    else:
        activity = invalid_param_activity
        service_name = activity_service_map[activity]
        client = get_client(service_name, region, role_arn)
        label = "🟧 파라미터 오류"

        try:
            activity(region, client)
            print(f"{label} - {role_name} - {activity.__name__} 성공")
        except Exception as e:
            print(f"{label} - {role_name} - {activity.__name__} 오류: {e}")

    time.sleep(random.uniform(0.5, 2.0))