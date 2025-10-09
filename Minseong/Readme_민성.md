# Malware Detection - IMG Analysis

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



## 실행 방법(로컬)
'''bash
### 환경세팅
  pip install tensorflow opencv-python numpy

### 실행
  python inference_workflow.py

### 입력 요청시 경로 지정
  1. 분석할 PE 파일 경로를 입력하세요 (예: C:/malware/sample.exe):
  2. 모델 파일 경로를 입력하세요 (예: ./PE_Inference_Assets/model/final_model_all_data.keras):

### 결과 저장 위치
  ./PE_Inference_Assets/inference_results/

'''



## 예측 결과 예시
''' json


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
'''

