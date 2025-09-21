# predict.py

import joblib
import re
import sys

# --- 1. 학습 때 사용했던 모든 설정과 함수를 그대로 가져옵니다 ---

# 1-1. Opcode 화이트리스트
OPCODE_WHITELIST = {
    'mov', 'lea', 'push', 'pop', 'pusha', 'popa', 'xchg', 'movzx', 'movsx',
    'add', 'sub', 'inc', 'dec', 'mul', 'imul', 'div', 'idiv', 'neg', 'sbb', 'adc',
    'and', 'or', 'xor', 'not', 'shl', 'shr', 'sar', 'rol', 'ror',
    'jmp', 'call', 'retn', 'ret', 'leave', 'enter',
    'je', 'jz', 'jne', 'jnz', 'jg', 'jnle', 'jge', 'jnl', 'jl', 'jnge', 'jle', 'jng',
    'ja', 'jae', 'jb', 'jbe', 'jc', 'jnc', 'jo', 'jno', 'jp', 'jpe', 'jnp', 'jpo',
    'js', 'jns',
    'cmp', 'test', 'setz', 'setnz', 'seta', 'setae', 'setb', 'setbe',
    'rep', 'repe', 'repne', 'movsb', 'movsd', 'stosb', 'stosd', 'cmpsb', 'scasb',
}

# 1-2. Opcode 추출 함수
def extract_opcodes_from_asm(filepath):
    """ .asm 파일에서 화이트리스트에 있는 Opcode만 추출합니다. (업그레이드 버전) """
    
    # ★★★★★ 수정된 정규식 ★★★★★
    # 새로운 형식을 처리하기 위해, 주소 뒤에 오는 Hex 코드를 건너뛰고 Opcode만 정확히 추출하도록 수정
    opcode_pattern = re.compile(r'^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2,}\s+)*([a-zA-Z]{2,})')
    
    filtered_opcodes = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = opcode_pattern.search(line)
                if match:
                    # 정규식의 첫 번째 그룹이 바로 Opcode가 됩니다.
                    opcode = match.group(1).lower()
                    if opcode in OPCODE_WHITELIST:
                        filtered_opcodes.append(opcode)
    except Exception as e:
        print(f"파일 처리 중 오류 발생: {e}")
    return filtered_opcodes


# --- 2. 예측을 수행하는 메인 함수 ---

def predict_asm_file(filepath):
    """
    하나의 .asm 파일을 입력받아 악성 여부를 예측합니다.
    근거가 불충분할 경우 '판단 불가'로 처리합니다.
    """
    # 1. 저장된 모델 파이프라인 로드 (기존과 동일)
    try:
        model_pipeline = joblib.load('malware_detection_model.joblib')
        vectorizer = model_pipeline['vectorizer']
        model = model_pipeline['model']
    except FileNotFoundError:
        print("오류: 'malware_detection_model.joblib' 파일을 찾을 수 없습니다.")
        return

    print(f"📄 파일 분석 시작: {filepath}")

    # 2. Opcode 추출 및 Trigram 생성 (기존과 동일)
    opcodes = extract_opcodes_from_asm(filepath)
    if not opcodes:
        print("분석할 유효한 Opcode를 찾을 수 없습니다.")
        return
    
    trigrams = [' '.join(opcodes[i:i+3]) for i in range(len(opcodes) - 2)]
    trigram_corpus = ' '.join(trigrams)

    # 3. TF-IDF 변환 (기존과 동일)
    tfidf_vector = vectorizer.transform([trigram_corpus])


    # ★★★★★ 새로 추가된 핵심 로직 ★★★★★
    # 4. 근거(Evidence) 확인
    # TF-IDF 벡터에서 0이 아닌 값의 개수(non-zero count)를 확인합니다.
    evidence_count = tfidf_vector.nnz

    print("--- 🔬 분석 결과 ---")

    # 만약 유효한 피처가 하나도 없다면 (근거가 0이라면)
    if evidence_count == 0:
        print("⚠️  예측: 판단 불가 (Indeterminate)")
        print("   (이유: 모델이 학습한 유효한 Opcode 패턴을 발견하지 못했습니다.)")
        print("   (권장: 패킹(Packed) 또는 난독화(Obfuscated)된 파일일 가능성이 높습니다.)")
        return # 여기서 함수를 종료하여 더 이상 예측을 진행하지 않음
    # ★★★★★ 로직 끝 ★★★★★


    # 5. 모델 예측 (근거가 충분할 경우에만 실행됨)
    prediction = model.predict(tfidf_vector)
    prediction_proba = model.predict_proba(tfidf_vector)

    # 6. 결과 출력 (기존과 동일)
    if prediction[0] == 1:
        print(f"🚨 예측: 악성코드 (Malware)")
        print(f"   (신뢰도: {prediction_proba[0][1]:.2%})")
    else:
        print(f"🛡️ 예측: 정상 파일 (Benign)")
        print(f"   (신뢰도: {prediction_proba[0][0]:.2%})")


# --- 3. 스크립트 실행 부분 ---

if __name__ == '__main__':
    # 터미널에서 파일 경로를 인자로 받습니다.
    if len(sys.argv) != 2:
        print("사용법: python predict.py <분석할_asm_파일_경로>")
    else:
        asm_file_path = sys.argv[1]
        predict_asm_file(asm_file_path)
