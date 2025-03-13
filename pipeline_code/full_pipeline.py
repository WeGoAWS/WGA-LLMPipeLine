import json
import random
import time
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

memory = ConversationBufferMemory(memory_key="chat_history", input_key="log_event")# LangChain 메모리 설정(대화기록 저장용)

log_analysis_prompt = PromptTemplate(# CloudTrail 로그 분석 프롬프트
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

policy_prompt = PromptTemplate(# IAM 정책 분석 프롬프트
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

llm = ChatBedrock(model_id="anthropic.claude-3-5-sonnet-20240620-v1:0", region_name="ap-northeast-2")

log_analysis_chain = log_analysis_prompt | llm
policy_analysis_chain = policy_prompt | llm

def find_latest_cloudtrail_files(bucket_name, prefix, file_count):  # 최신 CloudTrail 로그 여러 개 찾기
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    
    if "Contents" in response and response["Contents"]:
        # 최신 순으로 정렬
        sorted_files = sorted(response["Contents"], key=lambda x: x["LastModified"], reverse=True)
        
        # 가장 최신의 `file_count`개 파일 선택
        latest_files = [file["Key"] for file in sorted_files[:file_count]]
        return latest_files
    else:
        raise FileNotFoundError("No CloudTrail logs found in S3.")


def get_cloudtrail_logs(bucket_name, file_key):# CloudTrail 로그 가져오기
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    with gzip.GzipFile(fileobj=response["Body"]) as gz:
        logs = json.loads(gz.read().decode("utf-8"))
    return logs

def get_latest_events(logs, count):# CloudTrail 로그에서 최신 이벤트 가져오기
    records = logs.get("Records", [])
    records.sort(key=lambda x: x.get("eventTime", ""), reverse=True)# eventTime 기준 정렬
    return records[:count]


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



def retry_with_backoff(func, max_retries=8, base_delay=1.5):
    """지수적 백오프(Exponential Backoff)를 사용하여 요청을 재시도하는 함수"""
    retries = 0
    while retries < max_retries:
        try:
            return func()  # 요청 실행
        except botocore.exceptions.ClientError as e:
            if "ThrottlingException" in str(e):
                wait_time = (base_delay * (2 ** retries)) * random.uniform(0.8, 1.2)
                print(f"ThrottlingException 발생. {wait_time:.2f}초 후 재시도... ({retries + 1}/{max_retries})")
                time.sleep(wait_time)
                retries += 1
            else:
                raise  # 다른 예외는 그대로 발생
    raise Exception("최대 재시도 횟수를 초과했습니다.")

def analyze_log_with_bedrock(log):
    try:
        response = retry_with_backoff(lambda: log_analysis_chain.invoke({"log_event": json.dumps(log, indent=4)}))
        return response.content  # AIMessage에서 .content 가져오기
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        return "Analysis failed."


def analyze_policy_with_bedrock(log, user_arn):
    try:
        current_permissions = get_user_permissions(user_arn)
        response = retry_with_backoff(lambda: policy_analysis_chain.invoke({
            "log_event": json.dumps(log, indent=4),
            "current_permissions": json.dumps(current_permissions, indent=4)
        }))
        response_text = response.content  # AIMessage에서 .content 가져오기
    
        result = {"REMOVE": [], "ADD": [], "Reason": ""}
        for line in response_text.strip().split("\n"):
            if line.startswith("REMOVE:"):
                perms = line.replace("REMOVE:", "").strip()
                if perms != "None":
                    result["REMOVE"].append(perms)
            elif line.startswith("ADD:"):
                perms = line.replace("ADD:", "").strip()
                if perms != "None":
                    result["ADD"].append(perms)
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

def process_logs(bucket_name, log_prefix, output_bucket_name, output_file_key):
    print(f"Finding latest CloudTrail logs from S3: {bucket_name}/{log_prefix}") 
    file_count = 10  # 최신 file_count개의 파일을 가져옴
    latest_file_keys = find_latest_cloudtrail_files(bucket_name, log_prefix, file_count) 
    all_logs = []
    
    for file_key in latest_file_keys:
        print(f"Fetching {file_count} logs from S3: {bucket_name}/{file_key}")
        logs = get_cloudtrail_logs(bucket_name, file_key)
        all_logs.extend(logs.get("Records", []))  # 모든 파일의 로그를 합침

    count = 10  # 최신 count개의 이벤트만 가져옴
    print(f"Fetching latest {count} events from CloudTrail logs...")
    latest_events = get_latest_events({"Records": all_logs}, count)

    print("Analyzing logs and recommending IAM policies...")
    analysis_results = []
    for log in latest_events:
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")# 사용자 ARN 가져오기
        security_analysis = analyze_log_with_bedrock(log) 
        time.sleep(5)
        policy_recommendation = analyze_policy_with_bedrock(log, user_arn)
        time.sleep(5)
        analysis_results.append({
            "log_event": log,
            "analysis_comment": security_analysis,
            "policy_recommendation": policy_recommendation
        })

    print("Saving analysis results to S3...")
    save_analysis_to_s3(output_bucket_name, output_file_key, analysis_results)


process_logs("aws-cloudtrail-logs-863518424796-24295883", "AWSLogs/", "aws-cloudtrail-log-comment", "test_result.json")#전체 파이프라인 실행