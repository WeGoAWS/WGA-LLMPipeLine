import json
import logging
import re
import os
from datetime import datetime
from collections import defaultdict
from tqdm import tqdm
import boto3
from botocore.exceptions import ClientError
from langchain.chains import LLMChain
from langchain_core.prompts import PromptTemplate
from langchain_ollama import ChatOllama
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
import shutil
from datetime import datetime, timedelta
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# LLM 구성
ollama_model = "deepseek-r1:7b"
ollama_llm = ChatOllama(
    model=ollama_model,
    base_url="http://100.73.251.76:11434"
)

# 프롬프트 설정
log_analysis_prompt = PromptTemplate(
    input_variables=["log_event"],
    template="""You are a cloud security analyst reviewing AWS CloudTrail logs.

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

policy_prompt = PromptTemplate(
    input_variables=["log_event", "current_permissions", "action_context"],
    template="""
You are a cloud IAM policy expert. Based on the CloudTrail log, the user's current IAM permissions, and known information about AWS actions, analyze and recommend policy adjustments.

CloudTrail Log:
{log_event}

Current Permissions:
{current_permissions}

Action Context:
{action_context}
You must ONLY suggest IAM permission Action strings, such as "s3:ListBucket", ...
Do NOT include OpenID scopes, resource ARNs, roles, or unrelated strings.
Respond in the following JSON format:

{{
  "REMOVE": ["permission1", "permission2"],
  "ADD": ["permission3"],
  "Reason": "One-line rationale"
}}

Ensure the response is valid JSON. Do not include any explanation outside the JSON.
"""
)

log_analysis_chain = log_analysis_prompt | ollama_llm
policy_analysis_chain = policy_prompt | ollama_llm

# FAISS 벡터스토어 로드
def load_action_vectorstore(s3_bucket="wga-faiss-index", s3_prefix="faiss_index", local_dir="/tmp/faiss_index"):
    s3 = boto3.client("s3")
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir)
    os.makedirs(local_dir, exist_ok=True)

    response = s3.list_objects_v2(Bucket=s3_bucket, Prefix=s3_prefix)
    for obj in response.get("Contents", []):
        key = obj["Key"]
        filename = os.path.basename(key)
        if not filename:
            continue
        local_path = os.path.join(local_dir, filename)
        s3.download_file(s3_bucket, key, local_path)
        logging.info(f"Downloaded FAISS index file {key} to {local_path}")

    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    return FAISS.load_local(local_dir, embeddings, allow_dangerous_deserialization=True)


def yesterday_s3(s3_bucket):
    s3 = boto3.client("s3")
    yesterday = datetime.utcnow().date() - timedelta(days=1)
    prefix = f"{yesterday.strftime('%Y/%m/%d')}/"  # 예: "2025/03/28/"

    logging.info(f"Listing S3 keys under prefix: {prefix}")
    s3_keys = []

    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=s3_bucket, Prefix=prefix):
        for obj in page.get('Contents', []):
            s3_keys.append(obj['Key'])

    logging.info(f"Found {len(s3_keys)} log files for {yesterday}")
    return s3_keys
# 유사 문서 검색
def get_action_context(query_list, vectorstore, k=3):
    context_chunks = []
    for query in query_list:
        docs = vectorstore.similarity_search(query, k=k)
        if docs:
            context_chunks.append(f"[{query}]\n" + "\n".join([doc.page_content for doc in docs]))
    return "\n\n".join(context_chunks)

# 로그 분석
def analyze_log(log, action_vectorstore=None):
    try:
        raw_text = json.dumps(log, indent=4)
        actions = re.findall(r'"eventName"\s*:\s*"(\w+)"', raw_text)
        action_context = get_action_context(actions, action_vectorstore) if action_vectorstore else ""

        response = log_analysis_chain.invoke({
            "log_event": raw_text + ("\n\n=== Related AWS Action Info ===\n" + action_context if action_context else "")
        })

        response_text = response.content if hasattr(response, "content") else str(response)
        json_match = re.search(r"```json\s*(\{.*?\})\s*```", response_text, re.DOTALL)
        if not json_match:
            json_match = re.search(r"(\{.*\"risk_level\".*\})", response_text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(1))
            risk_level = parsed.get("risk_level", "Unknown")
        else:
            parsed = None
            risk_level = "Unknown"
    except Exception as e:
        response_text = f"Failed to parse response: {e}"
        risk_level = "Unknown"

    return {
        "comment": response_text,
        "risk": risk_level
    }

# IAM 정책 유효성 검사
def is_valid_policy(json_obj):
    required_keys = {"REMOVE", "ADD", "Reason"}
    if not (
        isinstance(json_obj, dict)
        and required_keys.issubset(json_obj.keys())
        and isinstance(json_obj["REMOVE"], list)
        and isinstance(json_obj["ADD"], list)
        and isinstance(json_obj["Reason"], str)
    ):
        return False

    iam_action_pattern = re.compile(r"^[a-z0-9]+:[A-Z][a-zA-Z0-9]+$")
    json_obj["REMOVE"] = [perm for perm in json_obj["REMOVE"] if iam_action_pattern.match(perm)]
    json_obj["ADD"] = [perm for perm in json_obj["ADD"] if iam_action_pattern.match(perm)]
    return True

# 정책 분석
def analyze_policy(logs, action_vectorstore=None):
    try:
        user_arn = logs[0].get("userIdentity", {}).get("arn", "unknown")
        current_permissions = []

        all_logs_text = "\n\n".join([json.dumps(log, indent=4) for log in logs])
        actions = list({log.get("eventName", "") for log in logs if log.get("eventName")})
        action_context = get_action_context(actions, action_vectorstore) if action_vectorstore else ""

        response = policy_analysis_chain.invoke({
            "log_event": all_logs_text,
            "current_permissions": json.dumps(current_permissions, indent=4),
            "action_context": action_context
        })

        response_text = response.content if hasattr(response, "content") else str(response)
        result = {"REMOVE": [], "ADD": [], "Reason": ""}

        json_match = re.search(r"(\{.*\"Reason\".*\})", response_text, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                if is_valid_policy(parsed):
                    return parsed
            except json.JSONDecodeError:
                pass

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

        is_valid_policy(result)
        return result

    except Exception as e:
        print(f"Error in policy analysis: {e}")
        return {"REMOVE": [], "ADD": [], "Reason": "Policy analysis failed."}

# S3에서 로그 파일 다운로드
def download_logs(bucket_name, object_key, local_file_path):
    s3 = boto3.client('s3')
    try:
        s3.download_file(bucket_name, object_key, local_file_path)
        logging.info(f"Downloaded {object_key} from {bucket_name} to {local_file_path}")
    except ClientError as e:
        logging.error(f"Error downloading {object_key} from {bucket_name}: {e}")
        raise

# S3에 분석 결과 업로드
def upload_analysis(bucket_name, object_key, analysis_results):
    s3 = boto3.client('s3')
    try:
        s3.put_object(Bucket=bucket_name, Key=object_key, Body=json.dumps(analysis_results, indent=4))
        logging.info(f"Uploaded analysis results to {bucket_name}/{object_key}")
    except ClientError as e:
        logging.error(f"Error uploading to {bucket_name}/{object_key}: {e}")
        raise
    
def process_logs(s3_buckets, output_bucket, output_key, action_vectorstore=None):
    all_logs = []
    yesterday = datetime.utcnow().date() - timedelta(days=1)

    for s3_bucket in s3_buckets:
        logging.info(f"Collecting logs from bucket: {s3_bucket}")
        s3 = boto3.client("s3")
        prefix = f"{yesterday.strftime('%Y/%m/%d')}/"

        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=s3_bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                local_file_path = f"/tmp/{os.path.basename(key)}"
                try:
                    download_logs(s3_bucket, key, local_file_path)
                    with open(local_file_path, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                        records = logs.get("Records", []) if isinstance(logs, dict) else logs
                        all_logs.extend(records)
                except Exception as e:
                    logging.error(f"Failed to process {key} from {s3_bucket}: {e}")
                    continue

    logging.info(f"총 수집된 로그 수: {len(all_logs)}")

    user_date_logs = defaultdict(lambda: defaultdict(list))
    for log in all_logs:
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")
        event_date = log.get("eventTime", "")[:10]
        user_date_logs[user_arn][event_date].append(log)

    analysis_results = []

    for user_arn, date_logs in tqdm(user_date_logs.items(), desc="사용자별 로그 분석 진행"):
        if user_arn == "unknown":
            continue
        for date_str, logs in tqdm(date_logs.items(), desc=f"{user_arn}의 날짜별 분석", leave=False):
            logging.info(f"Processing {len(logs)} log(s) for user '{user_arn}' on {date_str}")
            combined_log_text = "\n\n".join([json.dumps(log, indent=4) for log in logs])
            security_analysis = analyze_log({"log_event": combined_log_text}, action_vectorstore=action_vectorstore)
            policy_recommendation = analyze_policy(logs, action_vectorstore=action_vectorstore)
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
        logging.info(f"Processing global summary for {len(all_logs)} log(s)...")
        combined_all_text = "\n\n".join([json.dumps(log, indent=4) for log in all_logs])
        full_day_summary = analyze_log({"log_event": combined_all_text}, action_vectorstore=action_vectorstore)
        analysis_results.append({
            "type": "daily_global_summary",
            "log_count": len(all_logs),
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "analysis_comment": full_day_summary["comment"],
            "risk_level": full_day_summary["risk"]
        })

    upload_analysis(output_bucket, output_key, analysis_results)

# 실행
def main():
    s3_bucket = []  
    s3_keys = yesterday_s3(s3_bucket) 
    output_bucket = "wga-outputbucket"  
    output_key = f"results/{(datetime.utcnow().date() - timedelta(days=1)).isoformat()}-analysis.json"
    logging.info(f"Analyzing S3 files: {s3_keys} from {s3_bucket}")

    action_vectorstore = load_action_vectorstore()
    process_logs(s3_bucket, s3_keys, output_bucket, output_key, action_vectorstore=action_vectorstore)

if __name__ == "__main__":
    main()