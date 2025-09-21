import os, json, hashlib
import joblib
from extract_features import extract_features_from_path

MODEL_PATH = "../artifacts/model.pkl"
PE_PATH = "/home/alstn/Zoom.exe"      # 테스트용 파일
YARA_PATH = "../rules/packer.yar"     # 실제 경로에 맞게 수정

# --- 해시 함수 ---
def file_hashes(file_path: str):
    h_md5 = hashlib.md5()
    h_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h_md5.update(chunk)
            h_sha256.update(chunk)
    return h_md5.hexdigest(), h_sha256.hexdigest()

# --- 메인 ---
if __name__ == "__main__":
    model = joblib.load(MODEL_PATH)

    # 피처 추출
    X_one = extract_features_from_path(PE_PATH, yara_rules_path=YARA_PATH)

    # 예측
    prob = float(model.predict_proba(X_one)[0, 1])
    label = int(prob >= 0.5)

    # 해시 계산
    md5, sha256 = file_hashes(PE_PATH)

    # 결과 JSON
    result = {
        "file": PE_PATH,
        "hashes": {
            "md5": md5,
            "sha256": sha256,
        },
        "prediction": {
            "prob": prob*100,  # 0~100%
            "label": label,  # 0=정상, 1=악성
        },
        "features": X_one.to_dict(orient="records")[0],  # 필요 시 전체 피처도 포함
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    
# AWS Lambda 핸들러 예시
def lambda_handler(event, context):
    model = joblib.load(MODEL_PATH)

    # event에서 파일 경로 추출 (예: S3 이벤트)
    file_path = event.get("file_path", PE_PATH)  # 기본값은 테스트용 파일

    # 피처 추출
    X_one = extract_features_from_path(file_path, yara_rules_path=YARA_PATH)

    # 예측
    prob = float(model.predict_proba(X_one)[0, 1])
    label = int(prob >= 0.5)

    # 해시 계산
    md5, sha256 = file_hashes(file_path)

    # 결과 JSON
    result = {
        "file": file_path,
        "hashes": {
            "md5": md5,
            "sha256": sha256,
        },
        "prediction": {
            "prob": prob*100,
            "label": label,  # 0=정상, 1=악성
        },
        "features": X_one.to_dict(orient="records")[0],  # 필요 시 전체 피처도 포함
    }

    return {
        'statusCode': 200,
        'body': json.dumps(result, ensure_ascii=False)
    }