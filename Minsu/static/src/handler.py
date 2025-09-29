import os, json, hashlib
import joblib
from pathlib import Path
from extract_features import extract_features_from_path

# === 경로 설정 ===
BASE_DIR   = Path(__file__).resolve().parent.parent  
MODEL_PATH = BASE_DIR / "artifacts" / "static_model.pkl"
YARA_PATH  = BASE_DIR / "rules" / "packer.yar"
PE_PATH    = Path("/test/test.exe")  # 경로 수정 필요

# --- 해시 함수 ---
def file_hashes(file_path: Path):
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
    X_one = extract_features_from_path(str(PE_PATH), yara_rules_path=str(YARA_PATH))

    # 예측
    prob = float(model.predict_proba(X_one)[0, 1])
    label = int(prob >= 0.5)

    # 해시 계산
    md5, sha256 = file_hashes(PE_PATH)

    # 결과 JSON
    result = {
        "file": str(PE_PATH),
        "hashes": {
            "md5": md5,
            "sha256": sha256,
        },
        "prediction": {
            "label": label,
            "prob": prob,
            "prob_percent": f"{prob*100:.2f}%",
        },
        "features": X_one.to_dict(orient="records")[0],
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


# === AWS Lambda 핸들러 ===
def lambda_handler(event, context):
    model = joblib.load(MODEL_PATH)

    file_path = Path(event.get("file_path", PE_PATH))  # 기본값: 테스트용 파일

    X_one = extract_features_from_path(str(file_path), yara_rules_path=str(YARA_PATH))
    prob  = float(model.predict_proba(X_one)[0, 1])
    label = int(prob >= 0.5)
    md5, sha256 = file_hashes(file_path)

    result = {
        "file": str(file_path),
        "hashes": {
            "md5": md5,
            "sha256": sha256,
        },
        "prediction": {
            "label": label,                     # 0=정상, 1=악성
            "prob": prob,                       # 원래 확률값 (0~1)
            "prob_percent": f"{prob*100:.2f}%", # 퍼센트 문자열 (예: "0.78%")
        },
        "features": X_one.to_dict(orient="records")[0],
    }

    return {"statusCode": 200, "body": json.dumps(result, ensure_ascii=False)}
