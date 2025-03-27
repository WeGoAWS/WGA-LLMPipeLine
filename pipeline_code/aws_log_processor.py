import json
import gzip
import boto3
import botocore.exceptions
import logging
import re
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from langchain.chains import LLMChain
from langchain_core.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain_ollama import ChatOllama

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# AWS 클라이언트 설정
s3_client = boto3.client("s3")
iam_client = boto3.client("iam")

# LangChain 메모리
memory = ConversationBufferMemory(memory_key="chat_history")

# CloudTrail 로그 분석 프롬프트
log_analysis_prompt = PromptTemplate(
    input_variables=["log_event"],
    template="""
You are a cloud security analyst reviewing AWS CloudTrail logs.

Analyze the following AWS CloudTrail log event and answer the following questions in detail:

Log Event:
{log_event}

Respond in the following JSON format:

{{
  "assessment": "<Brief analysis>",
  "classification": "<Normal activity | Suspicious activity | Malicious activity>",
  "risk_level": "<None | Low | Medium | High>",
  "justification": "<Why this level was assigned>",
  "recommendation": "<Action recommendation>",
  "summary": "<One-sentence summary>"
}}

Only respond with a valid JSON object. Do not include any explanation outside the JSON.
"""
)


# IAM 정책 분석 프롬프트
policy_prompt = PromptTemplate(
    input_variables=["log_event", "current_permissions"],
    template="""
You are a cloud IAM policy expert. Based on the CloudTrail log and the user's current IAM permissions, analyze and recommend policy adjustments.

CloudTrail Log:
{log_event}

Current Permissions:
{current_permissions}

Respond in the following JSON format:

{{
  "REMOVE": ["permission1", "permission2"],  // or [] if none
  "ADD": ["permission3"],                    // or [] if none
  "Reason": "One-line rationale"
}}

Ensure the response is valid JSON. Do not include any explanation outside the JSON.
"""
)

# LangChain 실행 파이프라인 구성  
ollama_model = "deepseek-r1:7b"
ollama_llm = ChatOllama(model=ollama_model)
log_analysis_chain = log_analysis_prompt | ollama_llm
policy_analysis_chain = policy_prompt | ollama_llm
# 민감한 이벤트 목록
SENSITIVE_EVENTS = {
    "ConsoleLogin", "PutUserPolicy", "AttachUserPolicy",
    "CreateAccessKey", "UpdateAssumeRolePolicy"
}

def is_sensitive_event(event_name):
    return event_name in SENSITIVE_EVENTS

def find_latest_cloudtrail_files(bucket_name, prefix, file_count):
    paginator = s3_client.get_paginator('list_objects_v2')
    page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

    all_files = []
    for page in page_iterator:
        contents = page.get("Contents", [])
        for obj in contents:
            key = obj["Key"]
            if key.endswith(".gz"):  # CloudTrail 로그 파일만
                all_files.append({
                    "Key": key,
                    "LastModified": obj["LastModified"]
                })

    if not all_files:
        raise FileNotFoundError("No CloudTrail logs found in S3.")

    # 최근 순 정렬
    sorted_files = sorted(all_files, key=lambda x: x["LastModified"], reverse=True)
    latest_files = [file["Key"] for file in sorted_files[:file_count]]
    return latest_files

def get_cloudtrail_logs(bucket_name, file_key):
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    with gzip.GzipFile(fileobj=response["Body"]) as gz:
        logs = json.loads(gz.read().decode("utf-8"))
    return logs

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
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        for policy in attached_policies:
            policy_arn = policy["PolicyArn"]
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)["PolicyVersion"]["Document"]
            for statement in policy_document.get("Statement", []):
                if "Action" in statement:
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        permissions.add(actions)
                    else:
                        permissions.update(actions)
        inline_policies = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
        for policy_name in inline_policies:
            policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
            for statement in policy_document.get("Statement", []):
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
def analyze_log(log):
    try:
        response = log_analysis_chain.invoke({"log_event": json.dumps(log, indent=4)})
        response_text = response.content if hasattr(response, "content") else str(response)

        json_match = re.search(r"```json\s*(\{.*?\})\s*```", response_text, re.DOTALL) # JSON 코드 블록 찾기
        if not json_match:
            json_match = re.search(r"(\{.*\"risk_level\".*\})", response_text, re.DOTALL)# JSON 객체 찾기

        if json_match:# JSON 파싱 성공 시
            parsed = json.loads(json_match.group(1))# JSON 파싱
            risk_level = parsed.get("risk_level", "Unknown")# 위험 수준 추출
        else:
            parsed = None# 
            risk_level = "Unknown" 

    except Exception as e:
        response_text = f"Failed to parse response: {e}"
        risk_level = "Unknown"

    return {
        "comment": response_text,
        "risk": risk_level
    }

def analyze_policy(log, user_arn):
    try:
        current_permissions = get_user_permissions(user_arn)
        response = policy_analysis_chain.invoke({
            "log_event": json.dumps(log, indent=4),
            "current_permissions": json.dumps(current_permissions, indent=4)
        })
        response_text = response.content
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

def analyze_policy_multiple(logs, user_arn):
    try:
        current_permissions = get_user_permissions(user_arn)
        all_logs_text = "\n\n".join([json.dumps(log, indent=4) for log in logs])
        response = policy_analysis_chain.invoke({
            "log_event": all_logs_text,
            "current_permissions": json.dumps(current_permissions, indent=4)
        })
        response_text = response.content
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

def save_analysis_to_s3(bucket_name, file_key, analysis_results):
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=json.dumps(analysis_results, indent=4),
        ContentType="application/json"
    )

def process_combined_aws_logs(aws_bucket_name, aws_log_prefix, output_bucket_name, output_file_key, file_count=10, min_log_per_user=3):
    now = datetime.now(timezone.utc)
    one_day_ago = now - timedelta(days=1)

    all_logs = []
    aws_file_keys = find_latest_cloudtrail_files(aws_bucket_name, aws_log_prefix, file_count)

    for file_key in aws_file_keys:
        logs = get_cloudtrail_logs(aws_bucket_name, file_key)
        for record in logs.get("Records", []):
            try:
                event_time = datetime.strptime(record.get("eventTime", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                if one_day_ago <= event_time <= now:
                    all_logs.append(record)
            except Exception as e:
                print(f"Invalid eventTime in log: {e}")

    user_date_logs = defaultdict(lambda: defaultdict(list))
    for log in all_logs:
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")
        event_date = log.get("eventTime", "")[:10]
        user_date_logs[user_arn][event_date].append(log)

    analysis_results = []

    for user_arn, date_logs in user_date_logs.items():
        if user_arn == "unknown":
            continue
        for date_str, logs in date_logs.items():
            logging.info(f"Processing {len(logs)} log(s) for user '{user_arn}' on {date_str}")
            combined_log_text = "\n\n".join([json.dumps(log, indent=4) for log in logs])
            security_analysis = analyze_log({"log_event": combined_log_text})
            policy_recommendation = analyze_policy_multiple(logs, user_arn)
            analysis_results.append({
                "date": date_str,
                "user": user_arn,
                "log_count": len(logs),
                "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
                "analysis_comment": security_analysis["comment"],
                "risk_level": security_analysis["risk"],
                "policy_recommendation": policy_recommendation
            })

    if all_logs:
        logging.info(f"Processing full-day global summary for {len(all_logs)} log(s)...")
        combined_all_text = "\n\n".join([json.dumps(log, indent=4) for log in all_logs])
        full_day_summary = analyze_log({"log_event": combined_all_text})
        analysis_results.append({
            "type": "daily_global_summary",
            "log_count": len(all_logs),
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "analysis_comment": full_day_summary["comment"],
            "risk_level": full_day_summary["risk"]
        })

    save_analysis_to_s3(output_bucket_name, output_file_key, analysis_results)
    logging.info(f"Combined AWS log analysis complete. Result written to: {output_file_key}")

def main():
    aws_bucket_name = "normal-logs"
    aws_log_prefix = "AWSLogs/o-o388z0cstl/863518424796/CloudTrail/"
    output_bucket_name = "aws-cloudtrail-log-comment"
    output_file_key = "aws_result_freal.json"
    process_combined_aws_logs(aws_bucket_name, aws_log_prefix, output_bucket_name, output_file_key)

if __name__ == "__main__":
    main()