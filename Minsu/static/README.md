## 디렉토리 구조
static/
├─ artifacts/                # 모델과 피처 관련 산출물
│  ├─ feature_list.txt       # 최종 피처 목록
│  └─ model.pkl     # 학습된 모델
│
├─ src/                      # 패키지 코드
│  ├─ handler.py             # AWS 진입점 코드
│  └─ extract_features.py    # extract_features, preprocess_and_save
│
└─ rules/
   └─ packer.yar             # 야라 룰 파일 
   
## 실행 방법
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python src/handler.py
```
- handler.py 속 파일 경로를 수정해서 사용

## 예측 결과 예시(prob = 예측 확률)
```json
{
  "file": "/home/alstn/Zoom.exe",
  "hashes": {
    "md5": "b70c9349cfe93ae6f6d06f6410d9c1c6",
    "sha256": "ca3e8e557888186d1618190838d1d883f192eb5a363750203183916bb95513af"
  },
  "prediction": {
    "prob": 1.5571376116441684, 
    "label": 0 
  },
  "features": {
    "DllCharacteristics": 49504,
    "MajorImageVersion": 0,
    "MajorOperatingSystemVersion": 5,
    "SizeOfStackReserve": 1048576,
    "AddressOfEntryPoint": 120432,
    "Characteristics": 34,
    "SizeOfHeaders": 1024,
    "SizeOfInitializedData": 290304,
    "SizeOfUninitializedData": 0,
    "MinorSubsystemVersion": 2,
    "ImageBase": 5368709120,
    "MajorLinkerVersion": 14,
    "NumberOfSections": 6,
    "MinorImageVersion": 0,
    "SizeOfStackCommit": 4096,
    "e_lfanew": 280,
    "e_minalloc": 0,
    "e_ovno": 0,
    "Machine": 34404,
    "PointerToSymbolTable": 0,
    "NumberOfSymbols": 0,
    "SizeOfCode": 128000,
    "BaseOfCode": 4096,
    "SectionAlignment": 4096,
    "FileAlignment": 512,
    "imports_total": 478,
    "imports_unique": 477,
    "import_dlls_unique": 32,
    "imports_max_per_dll": 149,
    "imports_entropy": 5.185976953802916,
    "strings_entropy": 5.8471035201171,
    "strings_printable_ratio": 0.1069905084500154,
    "strings_avg_len": 13.329478138222848,
    "strings_base64_blob_count": 150,
    "yara_has_packer_generic": 0,
    "yara_count_packer": 0,
    "yara_has_upx_like": 0,
    "yara_has_mpress_like": 0,
    "yara_has_aspack_like": 0
  }
}
```