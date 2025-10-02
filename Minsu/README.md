# Malware Detection - Static Analysis

```text
- PE 파일 정적 분석 기반 악성코드 탐지를 위한 파이프라인입니다.
- PE 헤더, Import API, 문자열 통계, YARA 패커 탐지 피처를 추출하여 최종적으로 학습된 XGBoost 모델을 사용해 악성/정상을 분류합니다.
```

## 디렉토리 구조
```text
static/
├─ artifacts/                # 모델 및 피처 관련 산출물
│  ├─ pipeline.pkl           # 전처리 및 학습된 XGBoost 모델 파이프라인 
│  └─ feature_list.txt       # 최종 피처 목록 (순서 고정)
│
├─ src/
│  ├─ extract_features.py    # PE 피처 추출 코드
│  └─ handler.py             # 실행 및 AWS Lambda 핸들러
│
└─ rules/
   └─ packer.yar             # 패커 탐지용 YARA 룰
```

## 실행 환경 준비
```bash
# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 필요 라이브러리 설치
pip install -r requirements.txt
```

## 실행 방법
```bash
# handler.py 속 PE_PATH를 수정해 사용 
python src/handler.py
```

## 예측 결과 예시
```json
{
  "file": "/home/alstn/Zoom.exe",
  "hashes": {
    "md5": "b70c9349cfe93ae6f6d06f6410d9c1c6",
    "sha256": "ca3e8e557888186d1618190838d1d883f192eb5a363750203183916bb95513af"
  },
  "prediction": {
    "label": 0,
    "prob": 0.006077801808714867,
    "prob_percent": "0.61%"
  },
  "features": {
    "DllCharacteristics": 49504,
    "SizeOfStackReserve": 1048576,
    "AddressOfEntryPoint": 120432,
    "Characteristics": 34,
    "SizeOfHeaders": 1024,
    "SizeOfInitializedData": 290304,
    "SizeOfUninitializedData": 0,
    "SizeOfStackCommit": 4096,
    "SizeOfCode": 128000,
    "BaseOfCode": 4096,
    "SectionAlignment": 4096,
    "FileAlignment": 512,
    "ImageBase": 5368709120,
    "PointerToSymbolTable": 0,
    "NumberOfSymbols": 0,
    "imports_total": 478,
    "imports_unique": 477,
    "import_dlls_unique": 32,
    "imports_max_per_dll": 149,
    "strings_avg_len": 13.329478138222848,
    "strings_base64_blob_count": 150,
    "e_minalloc": 0,
    "e_ovno": 0,
    "MinorImageVersion": 0,
    "MajorImageVersion": 0,
    "MajorOperatingSystemVersion": 5,
    "MinorSubsystemVersion": 2,
    "MajorLinkerVersion": 14,
    "NumberOfSections": 6,
    "Machine": 34404,
    "imports_entropy": 5.185976953802916,
    "strings_entropy": 5.8471035201171,
    "strings_printable_ratio": 0.1069905084500154,
    "yara_has_packer_generic": 0,
    "yara_count_packer": 0,
    "yara_has_upx_like": 0,
    "yara_has_mpress_like": 0,
    "yara_has_aspack_like": 0,
    "e_lfanew": 280
  }
}
```