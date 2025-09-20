# -*- coding: utf-8 -*-
"""
feature_extract_service.py
- 사용 라이브러리: pefile(헤더), LIEF(임포트), re(문자열), yara-python(패커 탐지)
"""

from __future__ import annotations
import os, re, math
from typing import Dict, Optional
import pandas as pd
from pathlib import Path

import pefile
import lief
import yara

# 0) 스키마 (학습 CSV 기준) + YARA 룰
#    총 39개 피처 (순서 고정)
FEATURE_COLUMNS = [
    "DllCharacteristics","MajorImageVersion","MajorOperatingSystemVersion",
    "SizeOfStackReserve","AddressOfEntryPoint","Characteristics",
    "SizeOfHeaders","SizeOfInitializedData","SizeOfUninitializedData",
    "MinorSubsystemVersion","ImageBase","MajorLinkerVersion",
    "NumberOfSections","MinorImageVersion","SizeOfStackCommit",
    "e_lfanew","e_minalloc","e_ovno","Machine","PointerToSymbolTable","NumberOfSymbols",
    "SizeOfCode","BaseOfCode","SectionAlignment","FileAlignment",
    "imports_total","imports_unique","import_dlls_unique","imports_max_per_dll","imports_entropy",
    "strings_entropy","strings_printable_ratio","strings_avg_len","strings_base64_blob_count",
    "yara_has_packer_generic","yara_count_packer","yara_has_upx_like",
    "yara_has_mpress_like","yara_has_aspack_like",
]
_RULES: Optional[yara.Rules] = None  # 전역 캐시
DEFAULTS = {c: 0.0 for c in FEATURE_COLUMNS}
BASE_DIR = Path(__file__).resolve().parent
YARA_DEFAULT = str((BASE_DIR / "rules" / "packer.yar").resolve())

def compile_yara(path: str):
    if not (os.path.isfile(path) and path.lower().endswith((".yar", ".yara"))):
        raise FileNotFoundError(f"YARA file not found: {path}")
    # include 사용을 위해 네임스페이스 방식으로 컴파일
    return yara.compile(filepaths={"ns0": os.path.abspath(path)}, includes=True)

def get_yara_rules(path: Optional[str] = None):
    """룰 전역 캐시. path가 없으면 env → 기본 경로 순으로 사용."""
    global _RULES
    if _RULES is None:
        rule_path = path or os.environ.get("YARA_RULE_PATH") or YARA_DEFAULT
        _RULES = compile_yara(rule_path)
    return _RULES

def scan_packer_yara(raw_bytes: bytes, rules) -> Dict[str, int]:
    """패커 관련 YARA 피처 계산."""
    out = {
        "yara_has_packer_generic": 0, "yara_count_packer": 0,
        "yara_has_upx_like": 0, "yara_has_mpress_like": 0, "yara_has_aspack_like": 0,
    }
    try:
        matches = rules.match(data=raw_bytes, timeout=10)  # timeout 방어
        if not matches:
            return out

        uniq = {(m.namespace, m.rule) for m in matches}
        out["yara_count_packer"] = len(uniq)
        if out["yara_count_packer"] > 0:
            out["yara_has_packer_generic"] = 1

        # 키워드 판별(룰명+태그 기반)
        token_list, rule_names = [], []
        for m in matches:
            rule_names.append(m.rule)
            token_list.append(m.rule.lower())
            token_list.extend([t.lower() for t in m.tags])
        token_string = " ".join(token_list)

        out["yara_has_upx_like"]    = 1 if "upx" in token_string    else 0
        out["yara_has_aspack_like"] = 1 if "aspack" in token_string else 0

        # 'mpress'는 토큰 또는 정규식(단어 경계)로 탐지
        mpress_re = re.compile(r'(?<![A-Za-z0-9])mpress(?![A-Za-z0-9])', re.I)
        has_mpress = ("mpress" in token_string) or any(mpress_re.search(n) for n in rule_names)
        out["yara_has_mpress_like"] = 1 if has_mpress else 0

    except yara.TimeoutError:
        print("[YARA] scan timeout.")
    except Exception as e:
        print(f"[YARA] scan error: {e}")
    return out

# 2) 유틸
def _entropy(data: bytes | str) -> float:
    if data is None:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    n = len(data)
    if n == 0:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    ent = 0.0
    for v in counts.values():
        p = v / n
        ent -= p * math.log2(p)
    return float(ent)

def _ensure_schema(row: Dict[str, float]) -> pd.DataFrame:
    """누락 채움 + 순서 고정."""
    cleaned = {k: row.get(k, DEFAULTS[k]) for k in FEATURE_COLUMNS}
    return pd.DataFrame([cleaned], columns=FEATURE_COLUMNS)

# 3) 핵심: 바이트에서 피처 추출
def extract_features_from_bytes(file_bytes: bytes, yara_rules_path: Optional[str] = None) -> pd.DataFrame:
    feats: Dict[str, float] = {}

    # 3.1) PE 헤더 (pefile)
    pe = None
    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)

        def g(obj, attr, default=-1):
            return getattr(obj, attr, default) if obj else default

        feats["DllCharacteristics"]          = g(getattr(pe, "OPTIONAL_HEADER", None), "DllCharacteristics")
        feats["MajorImageVersion"]           = g(getattr(pe, "OPTIONAL_HEADER", None), "MajorImageVersion")
        feats["MajorOperatingSystemVersion"] = g(getattr(pe, "OPTIONAL_HEADER", None), "MajorOperatingSystemVersion")
        feats["SizeOfStackReserve"]          = g(getattr(pe, "OPTIONAL_HEADER", None), "SizeOfStackReserve")
        feats["AddressOfEntryPoint"]         = g(getattr(pe, "OPTIONAL_HEADER", None), "AddressOfEntryPoint")
        feats["Characteristics"]             = g(getattr(pe, "FILE_HEADER", None), "Characteristics")
        feats["SizeOfHeaders"]               = g(getattr(pe, "OPTIONAL_HEADER", None), "SizeOfHeaders")
        feats["SizeOfInitializedData"]       = g(getattr(pe, "OPTIONAL_HEADER", None), "SizeOfInitializedData")
        feats["SizeOfUninitializedData"]     = g(getattr(pe, "OPTIONAL_HEADER", None), "SizeOfUninitializedData")
        feats["MinorSubsystemVersion"]       = g(getattr(pe, "OPTIONAL_HEADER", None), "MinorSubsystemVersion")
        feats["ImageBase"]                   = g(getattr(pe, "OPTIONAL_HEADER", None), "ImageBase")
        feats["MajorLinkerVersion"]          = g(getattr(pe, "OPTIONAL_HEADER", None), "MajorLinkerVersion")
        feats["NumberOfSections"]            = g(getattr(pe, "FILE_HEADER", None), "NumberOfSections")
        feats["MinorImageVersion"]           = g(getattr(pe, "OPTIONAL_HEADER", None), "MinorImageVersion")
        feats["SizeOfStackCommit"]           = g(getattr(pe, "OPTIONAL_HEADER", None), "SizeOfStackCommit")
        feats["e_lfanew"]                    = g(getattr(pe, "DOS_HEADER", None),   "e_lfanew")
        feats["e_minalloc"]                  = g(getattr(pe, "DOS_HEADER", None),   "e_minalloc")
        feats["e_ovno"]                      = g(getattr(pe, "DOS_HEADER", None),   "e_ovno")
        feats["Machine"]                     = g(getattr(pe, "FILE_HEADER", None),  "Machine")
        feats["PointerToSymbolTable"]        = g(getattr(pe, "FILE_HEADER", None),  "PointerToSymbolTable")
        feats["NumberOfSymbols"]             = g(getattr(pe, "FILE_HEADER", None),  "NumberOfSymbols")
        # Magic / Subsystem 수집 안 함
        feats["SizeOfCode"]                  = g(getattr(pe, "OPTIONAL_HEADER", None), "SizeOfCode")
        feats["BaseOfCode"]                  = g(getattr(pe, "OPTIONAL_HEADER", None), "BaseOfCode")
        feats["SectionAlignment"]            = g(getattr(pe, "OPTIONAL_HEADER", None), "SectionAlignment")
        feats["FileAlignment"]               = g(getattr(pe, "OPTIONAL_HEADER", None), "FileAlignment")

    except Exception:
        # 파싱 실패 시 기본값
        for c in [
            "DllCharacteristics","MajorImageVersion","MajorOperatingSystemVersion",
            "SizeOfStackReserve","AddressOfEntryPoint","Characteristics",
            "SizeOfHeaders","SizeOfInitializedData","SizeOfUninitializedData",
            "MinorSubsystemVersion","ImageBase","MajorLinkerVersion",
            "NumberOfSections","MinorImageVersion","SizeOfStackCommit",
            "e_lfanew","e_minalloc","e_ovno","Machine","PointerToSymbolTable",
            "NumberOfSymbols","SizeOfCode","BaseOfCode","SectionAlignment","FileAlignment",
        ]:
            feats[c] = -1
    finally:
        if pe:
            try: pe.close()
            except Exception: pass

    # 3.2) Imports (LIEF 우선, pefile fallback)
    all_imports, dlls, imports_per_dll = [], set(), []
    try:
        lb = lief.PE.parse(file_bytes)
        if lb and getattr(lb, "imports", None):
            for entry in lb.imports:
                if entry.name:
                    dlls.add(entry.name.lower())
                    cnt = 0
                    for imp in entry.entries:
                        if imp.name:
                            all_imports.append(imp.name)
                            cnt += 1
                        elif getattr(imp, "is_ordinal", False):
                            all_imports.append(f"Ordinal_{imp.ordinal}")
                            cnt += 1
                    if cnt > 0:
                        imports_per_dll.append(cnt)
    except Exception:
        # pefile fallback
        try:
            pe2 = pefile.PE(data=file_bytes, fast_load=True)
            if hasattr(pe2, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe2.DIRECTORY_ENTRY_IMPORT:
                    name = (entry.dll or b"").decode("utf-8", "ignore").lower()
                    dlls.add(name)
                    cnt = 0
                    for imp in entry.imports:
                        if imp.name:
                            all_imports.append(imp.name.decode("utf-8", "ignore"))
                            cnt += 1
                    if cnt > 0:
                        imports_per_dll.append(cnt)
            try: pe2.close()
            except Exception: pass
        except Exception:
            pass

    feats["imports_total"] = len(all_imports)
    feats["imports_unique"] = len(set(all_imports))
    feats["import_dlls_unique"] = len(dlls)
    feats["imports_max_per_dll"] = max(imports_per_dll) if imports_per_dll else 0
    feats["imports_entropy"] = _entropy(''.join(all_imports)) if all_imports else 0.0

    # 3.3) 문자열 통계
    strings = re.findall(b"[\x20-\x7e]{4,}", file_bytes)
    printable_len = sum(len(s) for s in strings)
    feats["strings_entropy"] = _entropy(b"".join(strings))
    feats["strings_printable_ratio"] = (printable_len / len(file_bytes)) if file_bytes else 0.0
    feats["strings_avg_len"] = (printable_len / len(strings)) if strings else 0.0
    base64_blobs = re.findall(b'[A-Za-z0-9+/=]{20,}', file_bytes)
    feats["strings_base64_blob_count"] = len(base64_blobs)

    # 3.4) YARA (패커 계열)
    try:
        rules = get_yara_rules(yara_rules_path)  # None이면 자동 기본 경로 사용
        feats.update(scan_packer_yara(file_bytes, rules))
    except FileNotFoundError:
        # 룰 파일이 없으면 안전하게 0으로 채움
        feats.update({
            "yara_has_packer_generic": 0,
            "yara_count_packer": 0,
            "yara_has_upx_like": 0,
            "yara_has_mpress_like": 0,
            "yara_has_aspack_like": 0,
    })

    # 3.5) 최종 스키마 적용
    return _ensure_schema(feats)

# 4) 파일 경로 입력용 (편의 함수)
def extract_features_from_path(file_path: str, yara_rules_path: Optional[str] = None) -> pd.DataFrame:
    """파일 경로 → 1×N DataFrame (FEATURE_COLUMNS 순서)."""
    with open(file_path, "rb") as f:
        data = f.read()
    return extract_features_from_bytes(data, yara_rules_path)

# 5) (선택) API 경계용: DF → dict
def df_to_dict(df: pd.DataFrame) -> Dict[str, float]:
    """1×N DataFrame → dict (JSON 직렬화용)."""
    assert df.shape[0] == 1, "df must be a single-row DataFrame"
    return {c: float(df.iloc[0][c]) for c in df.columns}

__all__ = [
    "FEATURE_COLUMNS", "extract_features_from_bytes", "extract_features_from_path", "df_to_dict",
    "compile_yara", "get_yara_rules", "scan_packer_yara"
]
