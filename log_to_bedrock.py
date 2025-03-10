import json
import boto3
import gzip
import time
import botocore.exceptions
from langchain_community.chat_models import BedrockChat
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory

# AWS 클라이언트 설정
s3_client = boto3.client("s3")
bedrock_runtime = boto3.client("bedrock-runtime", region_name="ap-northeast-2")

# LangChain 메모리 설정 (이전 로그 분석을 위한 저장소)
memory = ConversationBufferMemory(memory_key="chat_history", input_key="log_event")

# LangChain 프롬프트 템플릿
log_analysis_prompt = PromptTemplate(
    input_variables=["log_event"],
    template="""
    Human: Analyze the following AWS CloudTrail log and determine if there are any security risks. 

    Log Data:
    {log_event}

    - Identify potential security risks.
    - Provide recommendations if needed.
    - Indicate if this event is normal or suspicious.

    Assistant:
    """
)

# LangChain LLM 설정
llm = BedrockChat(
    model_id="anthropic.claude-3-haiku-20240307-v1:0",
    region_name="ap-northeast-2"
)
# LangChain LLMChain 구성 (프롬프트 + 모델 결합)
llm_chain = LLMChain(llm=llm, prompt=log_analysis_prompt, memory=memory)

def find_latest_cloudtrail_file(bucket_name, prefix):
    """ 버킷에서 가장 최근 CloudTrail 로그 파일 찾기 """
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    
    if "Contents" in response and response["Contents"]:
        latest_file = max(response["Contents"], key=lambda x: x["LastModified"])
        return latest_file["Key"]
    else:
        raise FileNotFoundError("No CloudTrail logs found in S3.")

def get_cloudtrail_logs(bucket_name, file_key):
    """ CloudTrail 로그 가져오기 (gzip 압축 해제) """
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)

    with gzip.GzipFile(fileobj=response["Body"]) as gz:
        logs = json.loads(gz.read().decode("utf-8"))
    
    return logs

def get_latest_events(logs, count=5):
    """ count개의 최신 이벤트 가져오기 """
    events = logs.get("Records", [])
    return events[:count]

def analyze_log_with_bedrock(log):
    """ LangChain을 활용한 로그 분석 """
    try:
        response = llm_chain.run(log_event=json.dumps(log, indent=4))
        return response
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        return "Analysis failed."

def save_analysis_to_s3(bucket_name, file_key, analysis_results):
    """ 분석 결과를 S3에 저장 """
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=json.dumps(analysis_results, indent=4),
        ContentType="application/json"
    )

def process_logs(bucket_name, log_prefix, output_bucket_name, output_file_key):
    """ 전체 CloudTrail 로그 분석 및 저장 프로세스 """
    print(f"Finding latest CloudTrail log from S3: {bucket_name}/{log_prefix}")
    latest_file_key = find_latest_cloudtrail_file(bucket_name, log_prefix)

    print(f"Fetching logs from S3: {bucket_name}/{latest_file_key}")
    logs = get_cloudtrail_logs(bucket_name, latest_file_key)

    print("Fetching latest 5 events from CloudTrail logs...")
    latest_events = get_latest_events(logs, count=5)

    print("Analyzing logs with Claude 3 Haiku using LangChain...")
    analysis_results = []
    for log in latest_events:
        comment = analyze_log_with_bedrock(log)
        log["analysis_comment"] = comment
        analysis_results.append(log)

    print("Saving analysis results to S3...")
    save_analysis_to_s3(output_bucket_name, output_file_key, analysis_results)

    print("Log analysis stored in S3.")

# 실행 코드
input_bucket = "aws-cloudtrail-logs-863518424796-24295883"
log_prefix = "AWSLogs/863518424796/CloudTrail/ap-northeast-2/"

output_bucket = "aws-cloudtrail-log-comment"
output_file = "analysis-results/latest_logs_analysis.json"

process_logs(input_bucket, log_prefix, output_bucket, output_file)