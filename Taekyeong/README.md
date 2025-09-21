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
**1. 악성코드로 예측된 경우**
```
📄 파일 분석 시작: data/sample_malware/malicious_sample_1.asm

--- 🔬 분석 결과 ---
🚨 예측: 악성코드 (Malware)
   (신뢰도: 98.52%)
```
**2. 정상 파일로 예측된 경우**
```
📄 파일 분석 시작: data/sample_benign/benign_sample_1.asm

--- 🔬 분석 결과 ---
🛡️ 예측: 정상 파일 (Benign)
   (신뢰도: 99.25%)
```
**3. 판단이 불가능한 경우**
```
📄 파일 분석 시작: samples/packed_sample.asm

--- 🔬 분석 결과 ---
⚠️  예측: 판단 불가 (Indeterminate)
   (이유: 모델이 학습한 유효한 Opcode 패턴을 발견하지 못했습니다.)
   (권장: 패킹(Packed) 또는 난독화(Obfuscated)된 파일일 가능성이 높습니다.)
```
