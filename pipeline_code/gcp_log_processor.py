import json
import gzip
from google.cloud import storage
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain_ollama import ChatOllama

# GCP 클라이언트 설정
gcs_client = storage.Client()

# LangChain 메모리 (대화 기록 저장용)
memory = ConversationBufferMemory(memory_key="chat_history", input_key="log_event")

# 로그 분석 프롬프트
log_analysis_prompt = PromptTemplate(
    input_variables=["log_event"],
    template="""
    Human: Analyze the following GCP log and determine if there are any security risks.

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

# 정책 분석 프롬프트
policy_prompt = PromptTemplate(
    input_variables=["log_event", "current_permissions"],
    template="""
    Human: Based on the following GCP log and the user's current permissions, recommend policy modifications.

    GCP Log:
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

# LangChain 실행 파이프라인 구성 (Ollama 모델 사용)
ollama_model = "deepseek-r1:7b"
ollama_llm = ChatOllama(model=ollama_model)
log_analysis_chain = log_analysis_prompt | ollama_llm
policy_analysis_chain = policy_prompt | ollama_llm

def find_latest_gcp_files(bucket_name, prefix, file_count):
    bucket = gcs_client.get_bucket(bucket_name)
    blobs = bucket.list_blobs(prefix=prefix)
    sorted_files = sorted(blobs, key=lambda x: x.updated, reverse=True)
    latest_files = [blob.name for blob in sorted_files[:file_count]]
    return latest_files

def get_gcp_logs(bucket_name, file_key):
    bucket = gcs_client.get_bucket(bucket_name)
    blob = bucket.blob(file_key)
    content = blob.download_as_string()
    if file_key.endswith('.gz'):
        content = gzip.decompress(content)
    logs = json.loads(content.decode('utf-8'))
    return logs

def get_latest_events(logs, count):
    records = logs.get("Records", [])
    records.sort(key=lambda x: x.get("eventTime", ""), reverse=True)
    return records[:count]

# GCP 권한조회는 미구현
def get_user_permissions(user_identifier):
    return []

def analyze_log(log):
    try:
        response = log_analysis_chain.invoke({"log_event": json.dumps(log, indent=4)})
        return response.content
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        return "Analysis failed."

def analyze_policy(log, user_identifier):
    try:
        current_permissions = get_user_permissions(user_identifier)
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

def save_analysis_to_gcs(bucket_name, file_key, analysis_results):
    bucket = gcs_client.get_bucket(bucket_name)
    blob = bucket.blob(file_key)
    blob.upload_from_string(
        data=json.dumps(analysis_results, indent=4),
        content_type="application/json"
    )

def process_gcp_logs(gcp_bucket_name, gcp_log_prefix, output_bucket_name, output_file_key, file_count=5, event_count=5):
    all_logs = []
    gcp_file_keys = find_latest_gcp_files(gcp_bucket_name, gcp_log_prefix, file_count)
    for file_key in gcp_file_keys:
        logs = get_gcp_logs(gcp_bucket_name, file_key)
        all_logs.extend(logs.get("Records", []))
    all_logs.sort(key=lambda x: x.get("eventTime", ""), reverse=True)
    latest_events = all_logs[:event_count]
    analysis_results = []
    for log in latest_events:
        user_identifier = log.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail", "unknown")
        security_analysis = analyze_log(log)
        policy_recommendation = analyze_policy(log, user_identifier)
        analysis_results.append({
            "log_event": log,
            "user_identifier": user_identifier,
            "analysis_comment": security_analysis,
            "policy_recommendation": policy_recommendation
        })
    save_analysis_to_gcs(output_bucket_name, output_file_key, analysis_results)
    print("GCP log analysis complete.")

def main():
    gcp_bucket_name = "gcp-cloudtrail-logs"  # 실제 버킷명으로 변경
    gcp_log_prefix = "GCPLogs/"
    output_bucket_name = "gcp-log-analysis-results"  # 결과 저장 버킷명
    output_file_key = "gcp_result.json"
    process_gcp_logs(gcp_bucket_name, gcp_log_prefix, output_bucket_name, output_file_key)

if __name__ == "__main__":
    main()
