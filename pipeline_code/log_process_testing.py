import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Union
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain_ollama import ChatOllama
from langchain.schema import AIMessage


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s") 
memory = ConversationBufferMemory(memory_key="chat_history")

daily_user_analysis_prompt = PromptTemplate(
    input_variables=["log_event", "date", "user"],
    template="""
You are a cloud security analyst reviewing AWS CloudTrail logs for user {user} on {date}.

Analyze the following aggregated AWS CloudTrail log events and answer the following questions in detail:

Log Events:
{log_event}

1. Is the aggregated activity for user {user} on {date} indicative of any known security risks or misconfigurations?
2. Classify the overall activity as:
   - Normal activity
   - Suspicious activity
   - Malicious activity
3. Rate the severity of the risk (None, Low, Medium, High).
4. Explain why this risk level was assigned based on:
   - The actions performed
   - The resources involved
   - The user identity type (IAM user, role, root)
   - Whether MFA was used
   - Source IP or user agent anomalies
5. Recommend any of the following, if applicable:
   - IAM permission tightening
   - Policy change
   - Monitoring or alerting
   - No action required
6. Finally, summarize the aggregated activity in **one short, human-readable sentence**.

Respond in clearly labeled sections.
"""
)

daily_user_policy_prompt = PromptTemplate(
    input_variables=["log_event", "current_permissions", "date", "user"],
    template="""
You are a cloud IAM policy expert. Based on the aggregated CloudTrail logs for user {user} on {date} and the user's current IAM permissions, analyze and recommend policy adjustments.

CloudTrail Logs:
{log_event}

Current Permissions:
{current_permissions}

1. Are there any permissions that were not used in these logs and appear unnecessary?
2. Are there any actions in the logs that were blocked or would fail due to missing permissions?
3. Based on the aggregated activity, should any permissions be added or removed?

When modifying permissions:
- DO NOT remove permissions that were used multiple times across logs.
- DO NOT remove permissions that might cause service disruption.
- ONLY add permissions if they are required for observed activity.

Respond in the format below:

REMOVE: <list of permissions to remove or None>
ADD: <list of permissions to add or None>
Reason: <One-line rationale that justifies the change>
"""
)

# LangChain 실행 파이프라인
ollama_model = "deepseek-r1:7b"
ollama_llm = ChatOllama(model=ollama_model)
daily_user_analysis_chain = daily_user_analysis_prompt | ollama_llm
daily_user_policy_chain = daily_user_policy_prompt | ollama_llm

def analyze_daily_user_logs(logs: List[Dict[str, Any]], date: str, user: str) -> str:
    aggregated_logs = "\n\n".join([json.dumps(log, indent=4) for log in logs])
    try:
        logging.info(f"Analyzing logs for user '{user}' on {date} with {len(logs)} events...")
        response = daily_user_analysis_chain.invoke({
            "log_event": aggregated_logs,
            "date": date,
            "user": user
        })
        response_text = response.content if hasattr(response, "content") else str(response)
        logging.info("Daily-user log analysis complete.")
        return response_text
    except Exception as e:
        logging.error(f"Error in daily-user log analysis for user {user} on {date}: {e}")
        return "Daily-user log analysis failed."

def analyze_daily_user_policy(logs: List[Dict[str, Any]], date: str, user: str) -> Dict[str, Union[List[str], str]]:
    aggregated_logs = "\n\n".join([json.dumps(log, indent=4) for log in logs])
    try:
        logging.info(f"Analyzing IAM policy for user '{user}' on {date} with {len(logs)} events...")
        current_permissions: List[str] = []  # 현재 권한(이 코드에서는 일단 빈 리스트.)
        response = daily_user_policy_chain.invoke({
            "log_event": aggregated_logs,
            "current_permissions": json.dumps(current_permissions, indent=4),
            "date": date,
            "user": user
        })
        response_text = response.content if hasattr(response, "content") else str(response)
        logging.info("Daily-user IAM policy analysis complete.")
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
        logging.error(f"Error in IAM policy analysis for user {user} on {date}: {e}")
        return {"REMOVE": [], "ADD": [], "Reason": "Policy analysis failed."}

def make_json_serializable(obj: Any) -> Any:# JSON으로 직렬화 가능한 형태로 변환
    if isinstance(obj, AIMessage):
        return obj.content
    elif isinstance(obj, dict):
        return {key: make_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(item) for item in obj]
    else:
        return obj

def process_log(local_file: str, output_file: str) -> None:
    logging.info(f"Loading local logs from {local_file}...")
    try:
        with open(local_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load local logs: {e}")
        return

    if isinstance(data, list):# 로그 데이터가 리스트 형태로 들어올 경우
        records = data
    elif isinstance(data, dict) and "Records" in data: # 로그 데이터가 딕셔너리 형태로 들어올 경우
        records = data["Records"]
    else:
        logging.error("No valid log records found.")
        return

    day_user_logs: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))# 날짜별, 유저별 로그를 저장할 딕셔너리
    for log in records:
        event_time_str = log.get("eventTime", "")
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")
        try:
            event_date = datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%SZ").date()
            day_user_logs[str(event_date)][user_arn].append(log)
        except Exception as e:
            logging.error(f"Error parsing eventTime '{event_time_str}': {e}")

    analysis_results = []
    for date, user_logs in day_user_logs.items():
        for user, logs in user_logs.items():
            if user == "unknown":
                continue
            logging.info(f"Processing {len(logs)} log(s) for user '{user}' on {date}")
            security_analysis = analyze_daily_user_logs(logs, date, user)
            policy_recommendation = analyze_daily_user_policy(logs, date, user)
            analysis_results.append({
                "date": date,
                "user": user,
                "log_count": len(logs),
                "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
                "analysis_comment": security_analysis,
                "policy_recommendation": policy_recommendation
            })

    analysis_results_serializable = make_json_serializable(analysis_results)
    
    try:
        with open(output_file, "w") as f:
            json.dump(analysis_results_serializable, f, indent=4)
        logging.info(f"Day-and-user-based log analysis complete. Results saved to: {output_file}")
    except Exception as e:
        logging.error(f"Failed to save analysis results: {e}")

def main() -> None:
    num = 3
    local_file = f"flaws_cloudtrail00_split/part_{num}.json"
    output_file = f"output/test_{num}.json"
    process_log(local_file, output_file)

if __name__ == "__main__":
    main()