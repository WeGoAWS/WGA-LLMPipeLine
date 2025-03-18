import json
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain_ollama import ChatOllama

# LangChain 메모리 (대화 기록 저장용)
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

# IAM 정책 분석 프롬프트 (현재 권한은 빈 리스트로 전달)
policy_prompt = PromptTemplate(
    input_variables=["log_event", "current_permissions"],
    template="""
    Human: Based on the following CloudTrail log and an empty set of current permissions, recommend IAM policy modifications.

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

# LangChain 실행 파이프라인 구성  
ollama_model = "deepseek-r1:7b"
ollama_llm = ChatOllama(model=ollama_model)
log_analysis_chain = log_analysis_prompt | ollama_llm
policy_analysis_chain = policy_prompt | ollama_llm

def analyze_log(log):
    try:
        response = log_analysis_chain.invoke({"log_event": json.dumps(log, indent=4)})
        return response.content
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        return "Analysis failed."

def analyze_policy(log, user_arn):
    try:
        current_permissions = []  #일단 비워놨음
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

def process_local_logs(local_file, output_file, event_count=5):
    with open(local_file, "r") as f:
        data = json.load(f)
    
    if isinstance(data, list):#리스트면 그대로
        records = data
    elif isinstance(data, dict) and "Records" in data:#딕셔너리면 Records 키값에 있는 값
        records = data["Records"]
    else:
        print("No valid log records found.")
        return

    records.sort(key=lambda x: x.get("eventTime", ""), reverse=True)#시간순으로 정렬
    latest_events = records[:event_count]

    analysis_results = []
    for log in latest_events:
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")
        security_analysis = analyze_log(log)
        policy_recommendation = analyze_policy(log, user_arn)
        analysis_results.append({
            "log_event": log,
            "user_arn": user_arn,
            "analysis_comment": security_analysis,
            "policy_recommendation": policy_recommendation
        })
    
    with open(output_file, "w") as f:
        json.dump(analysis_results, f, indent=4)
    
    print("Local log analysis complete. Results saved to:", output_file)

def main():
    num = 1
    local_file = f"flaws_cloudtrail00_split/part_{num}.json"
    output_file = f"output/local_result_{num}.json"
    process_local_logs(local_file, output_file, event_count=10)
if __name__ == "__main__":
    main()
