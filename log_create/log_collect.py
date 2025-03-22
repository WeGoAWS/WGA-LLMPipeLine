import boto3
import gzip
import json
import os
from datetime import datetime, timedelta
from dateutil import tz
from io import BytesIO
from tqdm import tqdm  

# 사용자 설정
S3_BUCKET = 'normal-logs'
ACCOUNT_ID = '863518424796'
REGIONS = [
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-southeast-2',
    'eu-west-1',
    'us-east-1',
    'us-west-2'
]

# 수집 기간 (UTC 기준 ISO 포맷)
START_DATE = '2025-03-20T00:00:00'
END_DATE = '2025-03-23T00:00:00'
OUTPUT_DIR = './cloudtrail_logs_json'

# 날짜 파싱
start_dt = datetime.fromisoformat(START_DATE).astimezone(tz.UTC)
end_dt = datetime.fromisoformat(END_DATE).astimezone(tz.UTC)

# boto3 클라이언트
s3 = boto3.client('s3')

# 날짜 리스트 생성
date_list = [start_dt + timedelta(days=i) for i in range((end_dt - start_dt).days + 1)]

# 로그 키 수집
log_keys = []
for region in REGIONS:
    prefix_base = f"AWSLogs/o-o388z0cstl/{ACCOUNT_ID}/CloudTrail/{region}/"

    for dt in date_list:
        prefix = f"{prefix_base}{dt.year}/{dt.month:02d}/{dt.day:02d}/"
        continuation_token = None

        while True:
            if continuation_token:
                response = s3.list_objects_v2(
                    Bucket=S3_BUCKET,
                    Prefix=prefix,
                    ContinuationToken=continuation_token
                )
            else:
                response = s3.list_objects_v2(
                    Bucket=S3_BUCKET,
                    Prefix=prefix
                )

            for obj in response.get('Contents', []):
                if obj['Key'].endswith('.json.gz') and 'Digest' not in obj['Key']:  
                    log_keys.append(obj['Key'])

            if response.get('IsTruncated'):
                continuation_token = response.get('NextContinuationToken')
            else:
                break

print(f"수집된 로그 파일 수: {len(log_keys)}개")

# 로그 디렉토리 생성
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 로그 수집 및 압축 해제 (진행률 표시)
all_events = []
for key in tqdm(log_keys, desc="처리 중", unit="파일"):
    obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
    gz_stream = BytesIO(obj['Body'].read())
    with gzip.GzipFile(fileobj=gz_stream, mode='rb') as gz:
        data = json.load(gz)
        all_events.extend(data.get('Records', []))

# JSON 저장
output_path = os.path.join(OUTPUT_DIR, f"cloudtrail_{START_DATE[:10]}_to_{END_DATE[:10]}.json")
with open(output_path, 'w') as f:
    json.dump(all_events, f, indent=2)

print(f"{len(all_events)}개의 이벤트 저장")
print(f"저장 위치: {output_path}")
