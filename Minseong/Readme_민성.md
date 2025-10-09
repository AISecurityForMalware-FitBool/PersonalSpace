# Malware Detection - IMG Analysis

EfficientNetV2-S 기반 악성코드 이미지 분석 파이프라인입니다.  
PE(Portable Executable) 파일을 GrayScale 이미지로 변환하여 악성 여부를 추론합니다.

---

## 디렉토리 구조
```bash
IMG/
├─ PE_Inference_Assets/                 # <- 스크립트가 자동 생성하는 자산 폴더
│  ├─ model/                            # 학습된 EfficientNetV2-S 모델 저장
│  │  └─ final_model_all_data.keras
│  │
│  └─ inference_results/                # 추론 결과 저장
│     ├─ [PE파일명]_gray_300x300.png   # 변환된 PE GrayScale 이미지
│     └─ [PE파일명]_image_result.json  # 추론 결과 (JSON)
│
└─ inference_workflow.py                # 단일 추론 워크플로우 스크립트

--------------------------------------------------------------------------
## 환경 세팅
    pip install tensorflow opencv-python numpy

# 실행
    python inference_workflow.py

# 입력 요청 시 경로 지정
    1. 분석할 PE 파일 경로를 입력하세요 (예: C:/malware/sample.exe)
    2. 모델 파일 경로를 입력하세요 (예: ./PE_Inference_Assets/model/final_model_all_data.keras)

# 결과 저장 위치
    ./PE_Inference_Assets/inference_results/

--------------------------------------------------------------------------
# 예측 결과 예시

{
    "input_path": "/content/0b3731c524e6ba716f15087d85eae7e6225b6b51d4ae2fa6c142ff1523f57046.exe",
    "prediction": {
        "prob": 0.19639050960540771,
        "prob_percent": 19.63905143737793,
        "label": 0
    },
    "details": {
        "image_path": "./PE_Inference_Assets/inference_results/0b3731c524e6ba716f15087d85eae7e6225b6b51d4ae2fa6c142ff1523f57046_exe_gray_300x300.png",
        "model_path": "/content/final_model_all_data.keras"
    }
}


───────────────────────────────────────────────
🧠 [출력 로그 예시]

🚀 PE 파일 분석 시작: ./sample.exe
✅ 최종 모델 로드 중...
✅ PE 파일 전처리 (바이트 -> GrayScale 이미지 300x300) 중...
✅ 모델 예측 수행 중...

=============== 🔮 분석 결과 ===============
PE 파일명: sample.exe
예측 클래스: Normal
악성(Malware) 확률: 19.64%
정상(Normal) 확률: 80.36%
이미지 저장 경로: ./PE_Inference_Assets/inference_results/sample_exe_gray_300x300.png
==========================================

✅ JSON 결과 저장 완료: ./PE_Inference_Assets/inference_results/sample_exe_image_result.json
