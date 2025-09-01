import pandas as pd
import numpy as np # np.nan을 사용하기 위해 numpy import

def clean_csv_by_label(input_csv, output_csv, label_col="label", target_label="normal"):
    """
    특정 레이블(`target_label`)의 행들에서 전부 'None'인 열을 삭제하고 새로운 CSV 저장
    """
    # CSV 읽기
    df = pd.read_csv(input_csv)

    if label_col not in df.columns:
        raise ValueError(f"CSV에 '{label_col}' 컬럼이 없습니다.")

    # 특정 레이블에 해당하는 행만 선택
    target_rows = df[df[label_col] == target_label]

    # 결측값(NaN)을 처리하기 위해 pd.isnull() 사용
    # 모든 행이 결측값인 열 찾기
    cols_to_drop = target_rows.columns[target_rows.isnull().all()]

    # label 컬럼은 절대 삭제하지 않도록 제외
    cols_to_drop = [col for col in cols_to_drop if col != label_col]

    # 해당 열 삭제
    df_cleaned = df.drop(columns=cols_to_drop)

    # 결과 저장
    df_cleaned.to_csv(output_csv, index=False)

    print(f"✅ 완료: {output_csv} 에 저장됨")
    print(f"삭제된 열 개수: {len(cols_to_drop)}")
    if cols_to_drop:
        print("삭제된 열 목록:", cols_to_drop)

if __name__ == "__main__":
    input_file = "pe_features_full.csv"   # 기존 추출 CSV
    output_file = "features_cleaned.csv"  # 정리된 CSV

    clean_csv_by_label(input_file, output_file, label_col="label", target_label="normal")
