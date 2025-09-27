
## 디렉토리 구조

```
opcode-classifier/
|         
├── README.md              
├── requirements.txt       # 프로젝트 실행에 필요한 라이브러리 목록
|
├── src/
│   └── predict.py          # 새로운 파일 예측을 위한 최종 Python 스크립트
|
└──  model/
    └── malware_detection_model.joblib # 최종 저장된 모델 파일
    └── final_features.txt # 피처 목록
```




## 실행 방법
### 1. 환경 설정
```bash
# 1. 저장소 복제
git clone https://github.com/poatan2/opcode-classifier.git
cd opcode-classifier

# 2. (선택) 가상 환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate    # Windows

# 3. 필요 라이브러리 설치
pip install -r requirements.txt
```

### 2. 예측 스크립트 실행
`model/` 폴더에 저장된 모델을 사용하여 새로운 ASM 파일을 분석합니다.
```bash
python src/predict.py "path/to/your/sample.asm"
```



## 예측 결과
**1. 판단 가능한 경우**
```
{
  "file": "C:\\Users\\sample\\MLEngineStub.asm",
  "hashes": {
    "md5": "69d0f5fe632c16a052ded95716321cf2",
    "sha256": "c13f669a2ac0d7450ba721d1856dbcdbe50e5107068a7d65a7a8598392bd5d50"
  },
  "prediction": {
    "label": 0,
    "prob": 0.007786966860294342,
    "prob_percent": "0.78%"
  },
  "features": {
    "opcode_count": 9264,
    "trigram_count": 9262,
    "target_trigrams": {
      "mov mov cmp": 0.00993,
      "mov lea mov": 0.199031,
      "mov mov call": 0.055323,
      "mov jmp mov": 0.080661,
      "mov mov add": 0.000226,
      "mov mov mov": 0.90568,
      "test jz mov": 0.033993,
      "mov mov lea": 0.024131,
      "jz mov mov": 0.011951,
      "mov mov test": 0.020364,
      "mov call mov": 0.253379,
      "cmp jnz mov": 0.016224,
      "jmp mov mov": 0.012159,
      "call mov mov": 0.037373,
      "push push push": 0.064629,
      "pop pop pop": 0.067868,
      "mov test jz": 0.038029,
      "lea mov call": 0.017846,
      "lea call mov": 0.019897,
      "lea mov mov": 0.031369,
      "mov push call": 0.0,
      "mov imul mov": 0.002055,
      "mov push mov": 0.024928,
      "push call add": 0.0,
      "push push call": 0.0,
      "mov mov push": 0.013013,
      "push push mov": 0.000683,
      "imul mov mov": 0.000586,
      "mov push push": 0.005898,
      "mov mov imul": 0.000867,
      "mov mul mov": 0.00071,
      "push mov push": 0.03151,
      "push mov call": 0.001211,
      "push call mov": 0.0,
      "jnz mov mov": 0.005456,
      "mov add pop": 0.0,
      "push sub mov": 0.02095,
      "mov cmp jz": 0.006062,
      "call test jz": 0.020404,
      "call mov test": 0.015571,
      "cmp jz mov": 0.010652,
      "sub mov mov": 0.017477,
      "lea mov lea": 0.194342,
      "mov call test": 0.017924,
      "xor mov mov": 0.017875,
      "mov xor mov": 0.090113,
      "mov lea call": 0.017131
    },
    "evidence_count": 42
  }
}
```
**2. 판단이 불가능한 경우**
```
{
  "file": "C:\\Users\\sample\\Ld2yXjPFsUhkZGmb3lcp.asm",
  "hashes": {
    "md5": "58d46cafebb97d67a54717c787bf05c6",
    "sha256": "2c17b8868de139307bff2067e3e1287bff11521e4af8d296dc25f8ef65ff06dc"
  },
  "prediction": {
    "label": "Indeterminate",
    "reason": "Not enough opcodes."
  },
  "features": {
    "opcode_count": 0
  }
}
```
