# import os
# import pefile
# import pandas as pd
# import hashlib
# from collections import defaultdict

# # --- Configuration ---
# # 악성 파일과 정상 파일이 있는 디렉터리 경로를 설정합니다.
# MALICIOUS_DIR = '/Users/eden/Desktop/fitBool_eden/mal10ben40/mal'
# NORMAL_DIR = '//Users/eden/Desktop/fitBool_eden/mal10ben40/ben'
# OUTPUT_CSV = 'pe_features.csv'

# # API 카테고리를 정의합니다.
# api_categories = {
#     'synchronization': ['CreateMutex', 'CreateSemaphore', 'WaitForSingleObject'],
#     'dataexchange': ['ReadProcessMemory', 'WriteProcessMemory', 'MapViewOfFile'],
#     'file': ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile'],
#     'reckoning': ['GetSystemTime', 'GetTickCount', 'QueryPerformanceCounter'],
#     'memory': ['VirtualAlloc', 'VirtualFree', 'HeapAlloc', 'HeapFree'],
#     'execution': ['CreateProcess', 'ShellExecute', 'WinExec'],
#     'console': ['AllocConsole', 'FreeConsole'],
#     'diagnostic': ['OutputDebugStringA', 'IsDebuggerPresent'],
#     'dynamiclibrary': ['LoadLibrary', 'GetProcAddress'],
#     'storage': ['ReadEncryptedFileRaw', 'WriteEncryptedFileRaw'],
#     'resource': ['FindResource', 'LoadResource', 'SizeofResource'],
#     'windowing': ['CreateWindowEx', 'RegisterClass', 'ShowWindow'],
#     'network': ['socket', 'connect', 'send', 'recv', 'bind'],
#     'security': ['OpenProcessToken', 'AdjustTokenPrivileges'],
#     'registry': ['RegCreateKeyEx', 'RegSetValueEx', 'RegQueryValueEx'],
#     'services': ['CreateService', 'StartService', 'OpenSCManager'],
#     'rdp': ['WTSVirtualChannelOpen'],
#     'cryptography': ['CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash']
# }

# # --- Feature Extraction Function ---
# def get_pe_features(filepath):
#     """
#     하나의 PE 파일에서 지정된 피처들을 추출합니다.
#     """
#     features = defaultdict(lambda: 'None')  # 기본값으로 'None' 설정
#     features['file_name'] = os.path.basename(filepath)
#     features['file_size'] = os.path.getsize(filepath)

#     try:
#         # 해시 값 계산
#         with open(filepath, 'rb') as f:
#             data = f.read()
#             features['md5'] = hashlib.md5(data).hexdigest()
#             features['sha1'] = hashlib.sha1(data).hexdigest()
#             features['sha256'] = hashlib.sha256(data).hexdigest()

#         pe = pefile.PE(filepath)
        
#         # PE 헤더 정보
#         features['pe_header_timestamp'] = pe.FILE_HEADER.TimeDateStamp
#         features['pe_header_section_number'] = pe.FILE_HEADER.NumberOfSections
#         features['pe_header_size'] = pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfHeaders
#         features['pe_header_entrypoint'] = pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint
#         features['pe_header_filealignment'] = pe.NT_HEADERS.OPTIONAL_HEADER.FileAlignment
#         features['pe_header_sectionalignment'] = pe.NT_HEADERS.OPTIONAL_HEADER.SectionAlignment
        
#         # 섹션 정보
#         for section in pe.sections:
#             sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
#             if '.text' in sec_name:
#                 features['pe_header_sectionsize_text'] = section.SizeOfRawData
#                 features['entropy_section_text'] = section.get_entropy()
#             elif '.data' in sec_name:
#                 features['pe_header_sectionsize_data'] = section.SizeOfRawData
#                 features['entropy_section_data'] = section.get_entropy()
#             elif '.rdata' in sec_name:
#                 features['entropy_section_rdata'] = section.get_entropy()
#             elif '.reloc' in sec_name:
#                 features['entropy_section_reloc'] = section.get_entropy()
#             elif '.rsrc' in sec_name:
#                 features['entropy_section_rsrc'] = section.get_entropy()
        
#         # API Import 카운트
#         for category in api_categories:
#             features[f'pa_pe_apicount_{category}'] = 0
        
#         if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     api_name = imp.name.decode('utf-8', errors='ignore')
#                     for category, apis in api_categories.items():
#                         if any(api.lower() in api_name.lower() for api in apis):
#                             features[f'pa_pe_apicount_{category}'] += 1
        
#     except pefile.PEFormatError:
#         print(f"PEFormatError: {filepath} is not a valid PE file.")
#     except Exception as e:
#         print(f"Error processing {filepath}: {e}")
    
#     return features

# # --- Main Logic ---
# def main():
#     # 최종 데이터프레임 초기화
#     all_features = []

#     # 악성 파일 처리
#     print("Processing malicious files...")
#     malicious_files = [os.path.join(MALICIOUS_DIR, f) for f in os.listdir(MALICIOUS_DIR) if f.endswith('.exe')]
#     for i, file_path in enumerate(malicious_files[:10]):  # 10개만 처리
#         print(f"  [{i+1}/10] Extracting features from {file_path}")
#         features = get_pe_features(file_path)
#         features['label'] = 'malicious'
#         all_features.append(features)

#     print("\nProcessing normal files...")
#     # 정상 파일 처리
#     normal_files = [os.path.join(NORMAL_DIR, f) for f in os.listdir(NORMAL_DIR) if f.endswith('.exe')]
#     for i, file_path in enumerate(normal_files[:40]):  # 40개만 처리
#         print(f"  [{i+1}/40] Extracting features from {file_path}")
#         features = get_pe_features(file_path)
#         features['label'] = 'normal'
#         all_features.append(features)

#     # 데이터프레임으로 변환 및 CSV 저장
#     df = pd.DataFrame(all_features)
#     # 요청된 피처 순서대로 컬럼을 재정렬합니다.
#     desired_order = [
#         # 여기에 요청하신 108개 피처 이름을 순서대로 나열
#         'pa_pe_section_noname_flag', 'pa_pe_apicount_synchronization', 'pa_pe_apicount_dataexchange', 'pa_pe_apicount_file', 'pa_pe_apicount_reckoning', 'pa_pe_apicount_memory', 'pa_pe_apicount_execution', 'pa_pe_apicount_console', 'pa_pe_apicount_diagnostic', 'pa_pe_apicount_dynamiclibrary', 'pa_pe_apicount_storage', 'pa_pe_apicount_resource', 'pa_pe_apicount_windowing', 'pa_pe_apicount_network', 'pa_pe_apicount_security', 'pa_pe_apicount_registry', 'pa_pe_apicount_services', 'pa_pe_apicount_rdp', 'pa_pe_apicount_cryptography', 'md5', 'sha1', 'sha256', 'file_name', 'file_type', 'mime_type', 'file_size', 'av_detection_a', 'av_detection_b', 'av_detection_c', 'av_detection_d', 'pe_header_fileinfo_item_number', 'pe_header_timestamp', 'pe_header_api_import_number', 'pe_header_sectionsize_text', 'entropy_section_text', 'pe_header_sectionsize_data', 'entropy_section_data', 'pe_header_sectionsize_bss', 'entropy_section_rdata', 'entropy_section_reloc', 'entropy_section_rsrc', 'pe_header_section_md5', 'pe_header_sectionsize_second', 'pa_pe_section_notregular', 'pa_pe_section_regular', 'pe_header_flag_debug', 'pe_header_resource_languagecount_ENGLISH US', 'pe_header_resource_languagecount_NEUTRAL', 'pe_resourcecount_cursor', 'pa_pe_binarycontained', 'pe_resourcecount_icon', 'pe_resourcecount_rcdata', 'pe_resourcecount_string', 'pe_resourcecount_group_cursor', 'pe_resourcecount_group_icon', 'pe_header_size', 'pe_header_sectionsize_export', 'pe_header_sectionsize_import', 'pe_header_sectionsize_resource', 'pe_header_section_number', 'pe_header_baseofdata', 'pe_header_checksum', 'pe_header_dll_importnumber', 'pe_header_emaxalloc', 'pe_header_ecblp', 'pe_header_ecp', 'pe_header_ecparhdr', 'pe_header_elfanew', 'pe_header_esp', 'pe_header_entrypoint', 'pe_header_filealignment', 'pe_header_iat_rva', 'pe_header_fileversion', 'pe_header_flag_cfg', 'pe_header_flag_dep', 'pe_header_flag_image_dll_characteristics_appcontainer', 'pe_header_flag_image_dll_characteristics_high_entropy_va', 'pe_header_flag_image_dllcharacteristics_dynamic_base', 'pe_header_flag_image_dllcharacteristics_force_integrity', 'pe_header_flag_image_dllcharacteristics_no_bind', 'pe_header_flag_image_dllcharacteristics_no_isolation', 'pe_header_flag_image_dllcharacteristics_no_seh', 'pe_header_flag_image_dllcharacteristics_terminal_server_aware', 'pe_header_flag_image_dllcharacteristics_wdm_driver', 'pe_header_flag_image_file_32bit_machine', 'pe_header_flag_image_file_debug_stripped', 'pe_header_flag_image_file_dll', 'pe_header_flag_image_file_executable_image', 
#         'pe_header_flag_image_file_large_address_aware', 'pe_header_flag_image_file_line_nums_stripped', 'pe_header_flag_image_file_local_syms_stripped', 'pe_header_flag_image_file_net_run_from_swap', 'pe_header_flag_image_file_relocs_stripped', 'pe_header_flag_image_file_removable_run_from_swap', 'pe_header_flag_image_file_system', 'pe_header_flag_image_file_up_system_only', 'pe_header_loaderflags', 'pe_header_majorOSversion', 'pe_header_minorOSversion', 'pe_header_reloc_item_number', 'pe_header_data_item_number', 'pe_header_sectionalignment', 'pe_header_sizeofheaders', 'pe_header_sizeofheapcommit', 'pe_header_sizeofheapreserve', 'pe_header_sizeofimage', 'pe_header_sizeofstackcommit', 'pe_header_sizeofstackreserve','label' # 레이블 컬럼 추가
#     ]
#     # 실제 추출된 컬럼과 순서에 맞게 조정해야 합니다.
#     df = df.reindex(columns=df.columns)
    
#     df.to_csv(OUTPUT_CSV, index=False)
#     print(f"\nSuccessfully created {OUTPUT_CSV} with {len(df)} entries.")

# if __name__ == "__main__":
#     main()




import os
import pefile
import pandas as pd
import hashlib
from collections import defaultdict

# --- Configuration ---
# 악성 파일과 정상 파일이 있는 디렉터리 경로를 설정합니다.
MALICIOUS_DIR = '/Users/eden/Desktop/fitBool_eden/mal10ben40/mal'
NORMAL_DIR = '/Users/eden/Desktop/fitBool_eden/mal10ben40/ben'
OUTPUT_CSV = 'pe_features_full.csv'

# API 카테고리를 정의합니다.
api_categories = {
    'synchronization': ['CreateMutex', 'CreateSemaphore', 'WaitForSingleObject'],
    'dataexchange': ['ReadProcessMemory', 'WriteProcessMemory', 'MapViewOfFile'],
    'file': ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile'],
    'reckoning': ['GetSystemTime', 'GetTickCount', 'QueryPerformanceCounter'],
    'memory': ['VirtualAlloc', 'VirtualFree', 'HeapAlloc', 'HeapFree'],
    'execution': ['CreateProcess', 'ShellExecute', 'WinExec'],
    'console': ['AllocConsole', 'FreeConsole'],
    'diagnostic': ['OutputDebugStringA', 'IsDebuggerPresent'],
    'dynamiclibrary': ['LoadLibrary', 'GetProcAddress'],
    'storage': ['ReadEncryptedFileRaw', 'WriteEncryptedFileRaw'],
    'resource': ['FindResource', 'LoadResource', 'SizeofResource'],
    'windowing': ['CreateWindowEx', 'RegisterClass', 'ShowWindow'],
    'network': ['socket', 'connect', 'send', 'recv', 'bind'],
    'security': ['OpenProcessToken', 'AdjustTokenPrivileges'],
    'registry': ['RegCreateKeyEx', 'RegSetValueEx', 'RegQueryValueEx'],
    'services': ['CreateService', 'StartService', 'OpenSCManager'],
    'rdp': ['WTSVirtualChannelOpen'],
    'cryptography': ['CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash']
}

# 요청하신 109개 피처 이름을 순서대로 나열
desired_order = [
    'pa_pe_section_noname_flag', 'pa_pe_apicount_synchronization', 'pa_pe_apicount_dataexchange', 'pa_pe_apicount_file', 'pa_pe_apicount_reckoning', 'pa_pe_apicount_memory', 'pa_pe_apicount_execution', 'pa_pe_apicount_console', 'pa_pe_apicount_diagnostic', 'pa_pe_apicount_dynamiclibrary', 'pa_pe_apicount_storage', 'pa_pe_apicount_resource', 'pa_pe_apicount_windowing', 'pa_pe_apicount_network', 'pa_pe_apicount_security', 'pa_pe_apicount_registry', 'pa_pe_apicount_services', 'pa_pe_apicount_rdp', 'pa_pe_apicount_cryptography', 'md5', 'sha1', 'sha256', 'file_name', 'file_type', 'mime_type', 'file_size', 'av_detection_a', 'av_detection_b', 'av_detection_c', 'av_detection_d', 'pe_header_fileinfo_item_number', 'pe_header_timestamp', 'pe_header_api_import_number', 'pe_header_sectionsize_text', 'entropy_section_text', 'pe_header_sectionsize_data', 'entropy_section_data', 'pe_header_sectionsize_bss', 'entropy_section_rdata', 'entropy_section_reloc', 'entropy_section_rsrc', 'pe_header_section_md5', 'pe_header_sectionsize_second', 'pa_pe_section_notregular', 'pa_pe_section_regular', 'pe_header_flag_debug', 'pe_header_resource_languagecount_ENGLISH US', 'pe_header_resource_languagecount_NEUTRAL', 'pe_resourcecount_cursor', 'pa_pe_binarycontained', 'pe_resourcecount_icon', 'pe_resourcecount_rcdata', 'pe_resourcecount_string', 'pe_resourcecount_group_cursor', 'pe_resourcecount_group_icon', 'pe_header_size', 'pe_header_sectionsize_export', 'pe_header_sectionsize_import', 'pe_header_sectionsize_resource', 'pe_header_section_number', 'pe_header_baseofdata', 'pe_header_checksum', 'pe_header_dll_importnumber', 'pe_header_emaxalloc', 'pe_header_ecblp', 'pe_header_ecp', 'pe_header_ecparhdr', 'pe_header_elfanew', 'pe_header_esp', 'pe_header_entrypoint', 'pe_header_filealignment', 'pe_header_iat_rva', 'pe_header_fileversion', 'pe_header_flag_cfg', 'pe_header_flag_dep', 'pe_header_flag_image_dll_characteristics_appcontainer', 'pe_header_flag_image_dll_characteristics_high_entropy_va', 'pe_header_flag_image_dllcharacteristics_dynamic_base', 'pe_header_flag_image_dllcharacteristics_force_integrity', 'pe_header_flag_image_dllcharacteristics_no_bind', 'pe_header_flag_image_dllcharacteristics_no_isolation', 'pe_header_flag_image_dllcharacteristics_no_seh', 'pe_header_flag_image_dllcharacteristics_terminal_server_aware', 'pe_header_flag_image_dllcharacteristics_wdm_driver', 'pe_header_flag_image_file_32bit_machine', 'pe_header_flag_image_file_debug_stripped', 'pe_header_flag_image_file_dll', 'pe_header_flag_image_file_executable_image',
    'pe_header_flag_image_file_large_address_aware', 'pe_header_flag_image_file_line_nums_stripped', 'pe_header_flag_image_file_local_syms_stripped', 'pe_header_flag_image_file_net_run_from_swap', 'pe_header_flag_image_file_relocs_stripped', 'pe_header_flag_image_file_removable_run_from_swap', 'pe_header_flag_image_file_system', 'pe_header_flag_image_file_up_system_only', 'pe_header_loaderflags', 'pe_header_majorOSversion', 'pe_header_minorOSversion', 'pe_header_reloc_item_number', 'pe_header_data_item_number', 'pe_header_sectionalignment', 'pe_header_sizeofheaders', 'pe_header_sizeofheapcommit', 'pe_header_sizeofheapreserve', 'pe_header_sizeofimage', 'pe_header_sizeofstackcommit', 'pe_header_sizeofstackreserve','label'
]

# --- Feature Extraction Function ---
def get_pe_features(filepath):
    """
    하나의 PE 파일에서 지정된 피처들을 추출합니다.
    """
    # 109개 피처를 모두 None으로 초기화
    features = {col: 'None' for col in desired_order}

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            features['md5'] = hashlib.md5(data).hexdigest()
            features['sha1'] = hashlib.sha1(data).hexdigest()
            features['sha256'] = hashlib.sha256(data).hexdigest()

        features['file_name'] = os.path.basename(filepath)
        features['file_size'] = os.path.getsize(filepath)

        pe = pefile.PE(filepath)

        # -------------------
        # PE Header 정보
        # -------------------
        features['pe_header_timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['pe_header_section_number'] = pe.FILE_HEADER.NumberOfSections
        features['pe_header_size'] = pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfHeaders
        features['pe_header_entrypoint'] = pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint
        features['pe_header_filealignment'] = pe.NT_HEADERS.OPTIONAL_HEADER.FileAlignment
        features['pe_header_sectionalignment'] = pe.NT_HEADERS.OPTIONAL_HEADER.SectionAlignment
        features['pe_header_sizeofheaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features['pe_header_sizeofimage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['pe_header_sizeofheapcommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        features['pe_header_sizeofheapreserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        features['pe_header_sizeofstackcommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        features['pe_header_sizeofstackreserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['pe_header_loaderflags'] = pe.OPTIONAL_HEADER.LoaderFlags
        features['pe_header_majorOSversion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features['pe_header_minorOSversion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        features['pe_header_data_item_number'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        features['pe_header_checksum'] = pe.OPTIONAL_HEADER.CheckSum

        # -------------------
        # 섹션 정보
        # -------------------
        for section in pe.sections:
            sec_name = section.Name.decode(errors="ignore").strip("\x00")
            if '.text' in sec_name:
                features['pe_header_sectionsize_text'] = section.SizeOfRawData
                features['entropy_section_text'] = section.get_entropy()
            elif '.data' in sec_name:
                features['pe_header_sectionsize_data'] = section.SizeOfRawData
                features['entropy_section_data'] = section.get_entropy()
            elif '.bss' in sec_name:
                features['pe_header_sectionsize_bss'] = section.SizeOfRawData
            elif '.rdata' in sec_name:
                features['entropy_section_rdata'] = section.get_entropy()
            elif '.reloc' in sec_name:
                features['entropy_section_reloc'] = section.get_entropy()
            elif '.rsrc' in sec_name:
                features['entropy_section_rsrc'] = section.get_entropy()

        # 섹션 플래그
        features['pa_pe_section_noname_flag'] = int(any(s.Name.strip(b'\x00') == b'' for s in pe.sections))
        features['pa_pe_section_notregular'] = int(any(s.Name.decode(errors="ignore").startswith('!') for s in pe.sections))
        features['pa_pe_section_regular'] = int(any(s.Name.decode(errors="ignore").startswith('.') for s in pe.sections))

        # 두번째 섹션 크기
        if len(pe.sections) >= 2:
            features['pe_header_sectionsize_second'] = pe.sections[1].SizeOfRawData

        # 첫번째 섹션 MD5
        if pe.sections:
            features['pe_header_section_md5'] = pe.sections[0].get_hash_md5()

        # -------------------
        # API Imports
        # -------------------
        for cat in api_categories:
            features[f'pa_pe_apicount_{cat}'] = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = pe.DIRECTORY_ENTRY_IMPORT
            features['pe_header_api_import_number'] = sum(len(e.imports) for e in imports)
            features['pe_header_dll_importnumber'] = len(imports)
            for entry in imports:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode(errors="ignore")
                        for category, apis in api_categories.items():
                            if any(api.lower() in api_name.lower() for api in apis):
                                features[f'pa_pe_apicount_{category}'] += 1

        # -------------------
        # Reloc count
        # -------------------
        features['pe_header_reloc_item_number'] = len(getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []))

        # -------------------
        # FileInfo
        # -------------------
        features['pe_header_fileinfo_item_number'] = len(getattr(pe, 'FileInfo', []))
        try:
            features['pe_header_fileversion'] = pe.FileInfo[0].StringTable[0].entries.get(b'FileVersion', b'None').decode(errors='ignore')
        except:
            pass

        # -------------------
        # Flags
        # -------------------
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        file_chars = pe.FILE_HEADER.Characteristics

        features['pe_header_flag_cfg'] = int(dll_chars & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_GUARD_CF'])
        features['pe_header_flag_dep'] = int(dll_chars & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NX_COMPAT'])

        for name, mask in pefile.DLL_CHARACTERISTICS.items():
            features[f'pe_header_flag_{name.lower()}'] = int(dll_chars & mask)

        for name, mask in pefile.FILE_CHARACTERISTICS.items():
            features[f'pe_header_flag_{name.lower()}'] = int(file_chars & mask)

        # -------------------
        # 리소스 카운트
        # -------------------
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            lang_counts = defaultdict(int)
            type_counts = defaultdict(int)

            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.id in pefile.RESOURCE_TYPE:
                    rtype = pefile.RESOURCE_TYPE[entry.id]
                    type_counts[rtype] += 1
                if hasattr(entry, 'directory'):
                    for sub_entry in entry.directory.entries:
                        if hasattr(sub_entry, 'directory'):
                            for lang_entry in sub_entry.directory.entries:
                                lang_name = pefile.LANG_ID_TO_NAME.get(lang_entry.id, 'UNKNOWN')
                                lang_counts[lang_name] += 1

            features['pe_resourcecount_cursor'] = type_counts['RT_CURSOR']
            features['pe_resourcecount_icon'] = type_counts['RT_ICON']
            features['pe_resourcecount_rcdata'] = type_counts['RT_RCDATA']
            features['pe_resourcecount_string'] = type_counts['RT_STRING']
            features['pe_resourcecount_group_cursor'] = type_counts['RT_GROUP_CURSOR']
            features['pe_resourcecount_group_icon'] = type_counts['RT_GROUP_ICON']
            features['pe_header_resource_languagecount_ENGLISH US'] = lang_counts.get('ENGLISH US', 0)
            features['pe_header_resource_languagecount_NEUTRAL'] = lang_counts.get('NEUTRAL', 0)

        # -------------------
        # 기타
        # -------------------
        features['pa_pe_binarycontained'] = 1

    except Exception as e:
        print(f"Error processing {filepath}: {e}")

    return features



# --- Main Logic ---
def main():
    # 최종 데이터프레임 초기화
    all_features = []

    # 악성 파일 처리
    print("Processing malicious files...")
    malicious_files = [os.path.join(MALICIOUS_DIR, f) for f in os.listdir(MALICIOUS_DIR) if f.endswith('.exe')]
    for i, file_path in enumerate(malicious_files[:10]):  # 10개만 처리
        print(f"  [{i+1}/10] Extracting features from {file_path}")
        features = get_pe_features(file_path)
        features['label'] = 'malicious'
        all_features.append(features)

    print("\nProcessing normal files...")
    # 정상 파일 처리
    normal_files = [os.path.join(NORMAL_DIR, f) for f in os.listdir(NORMAL_DIR) if f.endswith('.exe')]
    for i, file_path in enumerate(normal_files[:40]):  # 40개만 처리
        print(f"  [{i+1}/40] Extracting features from {file_path}")
        features = get_pe_features(file_path)
        features['label'] = 'normal'
        all_features.append(features)

    # 데이터프레임으로 변환 및 CSV 저장
    df = pd.DataFrame(all_features)
    
    # 요청된 피처 순서대로 컬럼을 재정렬하고, 누락된 피처를 'None'으로 채웁니다.
    df = df.reindex(columns=desired_order, fill_value='None')
    
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSuccessfully created {OUTPUT_CSV} with {len(df)} entries and {len(df.columns)} columns.")

if __name__ == "__main__":
    main()