Malware-Detection-Pipeline/
├─ static/                      # PE Feature 기반 정적 분석 모듈
│  ├─ artifacts/                # 정적 분석 모델 및 피처 관련 산출물
│  │  ├─ pipeline.pkl           # 전처리 및 학습된 XGBoost 모델 파이프라인
│  │  └─ feature_list.txt       # 최종 피처 목록
│  ├─ src/                      # 정적 분석 실행 코드
│  │  ├─ extract_features.py    # PE 피처 추출 코드
│  │  └─ handler.py             # 메인 실행 핸들러
│  └─ rules/
│     └─ packer.yar             # 패커 탐지용 YARA 룰
│
├─ image/                       # PE 바이트 이미지 기반 분석 모듈
│  ├─ PE_Inference_Assets/       # 이미지 분석 결과 및 모델 저장소
│  │  ├─ model/
│  │  └─ inference_results/     # 이미지 분석 결과물 (PNG, JSON)
│  └─ inference_workflow.py      # 이미지 분석 메인 추론 스크립트
│
└─ requirements.txt             # 전체 프로젝트 필요 라이브러리

