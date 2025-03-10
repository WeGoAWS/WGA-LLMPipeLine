# main_pipeline.py (기존 기능 유지, ARN 추출 기능 분리)

import json
import boto3
import time
import botocore
import gzip
from langchain_core.prompts import PromptTemplate
from langchain_aws import ChatBedrock

s3_client = boto3.client("s3")

policy_prompt = PromptTemplate(
    input_variables=["log_event"],
    template="""
    Human: Analyze the following AWS CloudTrail log event and recommend IAM policy modifications in the EXACT format provided below.

    Log Data:
    {log_event}

    Format your response exactly as:
    REMOVE: <permissions or None>
    ADD: <permissions or None>
    Reason: <Clear explanation in one sentence.>
    """
)

llm = ChatBedrock(
    model_id="anthropic.claude-3-haiku-20240307-v1:0",
    region_name="ap-northeast-2"
)

chain = policy_prompt | llm
s3_client = boto3.client("s3")


def analyze_policy_with_bedrock(log):
    response = chain.invoke({"log_event": json.dumps(log, indent=4)})
    
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


def save_result_to_s3(bucket_name, file_key, result):
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=json.dumps(result, indent=4, ensure_ascii=False),
        ContentType="application/json"
    )
    print(f"Policy recommendation saved to S3: {bucket_name}/{file_key}")


def fetch_logs_from_s3(bucket_name, file_key):
    import gzip
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)

    with gzip.GzipFile(fileobj=response["Body"]) as gz:
        logs = json.loads(gz.read().decode("utf-8"))

    return logs["Records"]


def find_latest_logs(bucket_name, prefix, count=3):
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    if "Contents" in response and response["Contents"]:
        sorted_files = sorted(response["Contents"], key=lambda x: x["LastModified"], reverse=True)
        latest_files = [file["Key"] for file in sorted_files[:count]]
        print(f"Found latest {count} log files: {latest_files}")
        return latest_files
    else:
        raise FileNotFoundError("No logs found in S3.")


def analyze_policy_with_retry(log, max_retries=5, base_delay=10):
    import botocore
    for attempt in range(max_retries):
        try:
            return analyze_policy_with_bedrock(log)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ThrottlingException':
                wait_time = base_delay * (2 ** attempt)
                print(f"Throttled, retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise e
    raise Exception("Exceeded maximum retry attempts")


input_bucket = "your_bucket"
input_prefix = "your_prefix"
input_files = find_latest_logs(input_bucket, input_prefix, count=10)

output_bucket = "your_bucket"
output_file_prefix = "your_prefix"

for idx, input_file in enumerate(input_files):
    latest_log = fetch_logs_from_s3(input_bucket, input_file)
    policy_recommendation_result = analyze_policy_with_retry(latest_log)
    output_file = f"{output_file_prefix}policy_analysis_{idx+1}.json"
    save_result_to_s3(output_bucket, output_file, policy_recommendation_result)
