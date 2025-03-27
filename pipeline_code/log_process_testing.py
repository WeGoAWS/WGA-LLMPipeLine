import json
import logging
import re
import os
from datetime import datetime
from collections import defaultdict
from tqdm import tqdm

from langchain.chains import LLMChain
from langchain_core.prompts import PromptTemplate
from langchain_ollama import ChatOllama
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# LLM 구성
ollama_model = "deepseek-r1:7b"
ollama_llm = ChatOllama(model=ollama_model)

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

# FAISS 벡터 스토어 로딩 및 검색
def load_action_vectorstore(save_path="faiss_index"):
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    return FAISS.load_local(save_path, embeddings, allow_dangerous_deserialization=True)

def get_action_context(query_list, vectorstore, k=3):
    context_chunks = []
    for query in query_list:
        docs = vectorstore.similarity_search(query, k=k)# faiss에서 유사한 문서 검색
        if docs:
            context_chunks.append(f"[{query}]\n" + "\n".join([doc.page_content for doc in docs]))
    return "\n\n".join(context_chunks)

# 로그 분석
def analyze_log(log, action_vectorstore=None):
    try:
        raw_text = json.dumps(log, indent=4)
        actions = re.findall(r'"eventName"\s*:\s*"(\w+)"', raw_text)# eventName 추출
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

# 정책 추천
def analyze_policy_multiple(logs, action_vectorstore=None):
    try:
        user_arn = logs[0].get("userIdentity", {}).get("arn", "unknown")
        current_permissions = []  # 실제 IAM 권한 조회 대신 일단은 빈 리스트

        all_logs_text = "\n\n".join([json.dumps(log, indent=4) for log in logs])
        actions = list({log.get("eventName", "") for log in logs if log.get("eventName")})# 
        action_context = get_action_context(actions, action_vectorstore) if action_vectorstore else "" 

        response = policy_analysis_chain.invoke({
            "log_event": all_logs_text,
            "current_permissions": json.dumps(current_permissions, indent=4),
            "action_context": action_context
        })

        response_text = response.content
        result = {"REMOVE": [], "ADD": [], "Reason": ""}

        json_match = re.search(r"(\{.*\"Reason\".*\})", response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        else:
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

# JSON 로그 로딩
def get_logs(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# 결과 저장
def save_analysis(file_path, analysis_results):
    with open(file_path, 'w') as f:
        json.dump(analysis_results, f, indent=4)
    logging.info(f"Local analysis result saved to {file_path}")

# 로그 처리
def process_logs(local_file_paths, output_file_path, action_vectorstore=None):
    all_logs = []
    for file_path in local_file_paths:
        try:
            logs = get_logs(file_path)
        except Exception as e:
            logging.error(f"Error reading {file_path}: {e}")
            continue
        records = logs.get("Records", []) if isinstance(logs, dict) else logs
        all_logs.extend(records)

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
            policy_recommendation = analyze_policy_multiple(logs, action_vectorstore=action_vectorstore)
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

    save_analysis(output_file_path, analysis_results)

# 실행
def main():
    num = 11
    local_files = [f"flaws_cloudtrail00_split/part_{num}.json"]
    output_file_path = f"output/analysis_results_{num}.json"
    logging.info(f"Analyzing local files: {local_files}")

    action_vectorstore = load_action_vectorstore()
    process_logs(local_files, output_file_path, action_vectorstore=action_vectorstore)

if __name__ == "__main__":
    main()
