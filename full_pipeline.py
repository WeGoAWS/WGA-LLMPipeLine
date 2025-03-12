import json
import boto3
import gzip
import botocore.exceptions
from langchain_community.chat_models import BedrockChat
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain_aws import ChatBedrock
# AWS 클라이언트 설정
s3_client = boto3.client("s3")
iam_client = boto3.client("iam")
bedrock_runtime = boto3.client("bedrock-runtime", region_name="ap-northeast-2")

# LangChain 메모리 설정 (이전 로그 분석을 위한 저장소)
memory = ConversationBufferMemory(memory_key="chat_history", input_key="log_event")

# CloudTrail 로그 분석 프롬프트
log_analysis_prompt = PromptTemplate(
    input_variables=["log_event"],
    template="""
    Human: Analyze the following AWS CloudTrail log and determine if there are any security risks.

    Log Data:
    {log_event}

    - Identify potential security risks.
    - Clearly explain the risk level (Low, Medium, High).
    - Provide recommendations if needed.
    - Indicate if this event is normal or suspicious.
    - Provide a summary of the event in a short, human-readable format.

    Assistant:
    """
)

# IAM 정책 추천 프롬프트
policy_prompt = PromptTemplate(
    input_variables=["log_event", "current_permissions"],
    template="""
    Human: Based on the following CloudTrail log and the user's current permissions, recommend IAM policy modifications.

    CloudTrail Log:
    {log_event}

    Current Permissions:
    {current_permissions}

    - Only remove permissions if they are **clearly unnecessary** based on the log.
    - If a permission has been used multiple times, do not remove it.
    - If additional permissions are needed, provide them.
    - If the log suggests a need for more restrictive permissions, recommend policy adjustments.
    - Provide a reason for each change.

    Format your response exactly as:
    REMOVE: <permissions or None>
    ADD: <permissions or None>
    Reason: <Clear explanation in one sentence.>
    """
)

llm = BedrockChat(model_id="anthropic.claude-3-haiku-20240307-v1:0", region_name="ap-northeast-2")# Bedrock 모델 설정

log_analysis_chain = log_analysis_prompt | llm
policy_analysis_chain = policy_prompt | llm

def find_latest_cloudtrail_file(bucket_name, prefix):# 최신 CloudTrail 로그 파일 찾기(키값 반환)
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    if "Contents" in response and response["Contents"]:
        latest_file = max(response["Contents"], key=lambda x: x["LastModified"])
        return latest_file["Key"]
    else:
        raise FileNotFoundError("No CloudTrail logs found in S3.")

def get_cloudtrail_logs(bucket_name, file_key):# CloudTrail 로그 가져오기
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    with gzip.GzipFile(fileobj=response["Body"]) as gz:
        logs = json.loads(gz.read().decode("utf-8"))
    return logs

def get_latest_events(logs, count):# CloudTrail 로그에서 최신 이벤트 가져오기
    return logs.get("Records", [])[:count]


def get_user_permissions(user_arn):
    if user_arn.endswith(":root"):
        print(f"Skipping root user: {user_arn}")
        return []

    if ":user/" in user_arn:
        user_name = user_arn.split("user/")[-1]
    elif ":assumed-role/" in user_arn:
        print(f"Skipping assumed-role: {user_arn}")
        return []
    else:
        raise ValueError(f"Invalid IAM ARN format: {user_arn}")

    permissions = set()
    
    try:
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []) # Attached Policies 가져오기
        for policy in attached_policies:# Attached Policies 가져오기
            policy_arn = policy["PolicyArn"]# arn 가져오기
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]# Policy 버전 가져오기
            policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)["PolicyVersion"]["Document"]# Policy 문서 가져오기
            
            for statement in policy_document.get("Statement", []):
                if "Action" in statement:
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        permissions.add(actions)
                    else:
                        permissions.update(actions)

        inline_policies = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])# Inline Policies 가져오기
        for policy_name in inline_policies:
            policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]# Policy 문서 가져오기
            for statement in policy_document.get("Statement", []):#
                if "Action" in statement: 
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        permissions.add(actions)
                    else:
                        permissions.update(actions)

    except botocore.exceptions.ClientError as e:
        print(f"Error fetching IAM policies for {user_name}: {e}")
        return []

    return list(permissions)

def analyze_log_with_bedrock(log):# CloudTrail 로그 분석
    try:
        response = log_analysis_chain.invoke({"log_event": json.dumps(log, indent=4)}) # 프롬프트 실행
        return response.content
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        return "Analysis failed."

def analyze_policy_with_bedrock(log, user_arn):
    try:
        current_permissions = get_user_permissions(user_arn)
        response = policy_analysis_chain.invoke({
            "log_event": json.dumps(log, indent=4),
            "current_permissions": json.dumps(current_permissions, indent=4)
        })
        response_text = response.content
    
        result = {"REMOVE": [], "ADD": [], "Reason": ""}# 결과 초기화
        for line in response_text.strip().split("\n"):# 결과 파싱
            if line.startswith("REMOVE:"):# REMOVE:으로 시작하는 경우
                perms = line.replace("REMOVE:", "").strip()# 권한 가져오기
                if perms != "None": 
                    result["REMOVE"].append(perms)# 결과에 추가
            elif line.startswith("ADD:"):# ADD:으로 시작하는 경우
                perms = line.replace("ADD:", "").strip()# 권한 가져오기
                if perms != "None": 
                    result["ADD"].append(perms)# 결과에 추가
            elif line.startswith("Reason:"):
                result["Reason"] = line.replace("Reason:", "").strip()
        return result
    except Exception as e:
        print(f"Error in policy analysis: {e}")
        return {"REMOVE": [], "ADD": [], "Reason": "Policy analysis failed."}


def save_analysis_to_s3(bucket_name, file_key, analysis_results):# 분석 결과를 S3에 저장
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=json.dumps(analysis_results, indent=4),
        ContentType="application/json"
    )

def process_logs(bucket_name, log_prefix, output_bucket_name, output_file_key):# 
    print(f"Finding latest CloudTrail log from S3: {bucket_name}/{log_prefix}") 
    latest_file_key = find_latest_cloudtrail_file(bucket_name, log_prefix)

    print(f"Fetching logs from S3: {bucket_name}/{latest_file_key}")#
    logs = get_cloudtrail_logs(bucket_name, latest_file_key)
    count = 10# 최신 count개의 이벤트만 가져옴
    print(f"Fetching latest {count} events from CloudTrail logs...")
    latest_events = get_latest_events(logs, count)

    print("Analyzing logs and recommending IAM policies...")
    analysis_results = []
    for log in latest_events:
        
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")
        
        security_analysis = analyze_log_with_bedrock(log)
        policy_recommendation = analyze_policy_with_bedrock(log, user_arn)
        analysis_results.append({
            "log_event": log,
            "analysis_comment": security_analysis,
            "policy_recommendation": policy_recommendation
        })

    print("Saving analysis results to S3...")
    save_analysis_to_s3(output_bucket_name, output_file_key, analysis_results)

process_logs("aws-cloudtrail-logs-863518424796-24295883", "AWSLogs/", "aws-cloudtrail-log-comment", "test_result.json")#전체 파이프라인 실행