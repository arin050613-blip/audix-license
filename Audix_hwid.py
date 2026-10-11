import os
import sys
import hashlib
import subprocess
import glob
import struct
import json
import urllib.request
import threading
import winreg
import datetime
import ctypes
import tkinter as tk
from tkinter import messagebox

# 필수 라이브러리(customtkinter) 설치 여부 확인 및 안내
try:
    import customtkinter as ctk
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Audix Studio Stereo Patcher - 필수 라이브러리 누락",
        "CustomTkinter 라이브러리가 설치되어 있지 않습니다.\n\n"
        "명령 프롬프트(CMD)를 열고 아래 명령어를 입력하여 설치해주세요:\n\n"
        "pip install customtkinter"
    )
    sys.exit(1)

# ============================================================================
# [원격 API 하드락 설정] 서버/URL 기반 HWID 동적 인증 관리
# ============================================================================
def get_hwid() -> str:
    try:
        cmd = 'powershell -Command "Get-CimInstance Win32_DiskDrive | Select-Object -First 1 -ExpandProperty SerialNumber"'
        output = subprocess.check_output(cmd, shell=True, text=True, errors='ignore').strip()
        if output:
            return output
    except Exception:
        pass
        
    try:
        cmd = "wmic diskdrive get serialnumber"
        output = subprocess.check_output(cmd, shell=True, text=True, errors='ignore')
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        if len(lines) > 1 and lines[1].strip():
            return lines[1].strip()
    except Exception:
        pass
        
    return ""

def fetch_authorized_hwids() -> list:
    """원격 서버(API/URL)에서 허용된 HWID 목록을 불러옵니다."""
    # 여기에 본인이 제어할 수 있는 JSON 파일 주소를 입력하세요.
    # 예시: GitHub Gist, Raw 파일, 개인 웹서버 등
    auth_url = "https://raw.githubusercontent.com/아이디/저장소/main/allowed_hwids.json"
    try:
        req = urllib.request.Request(auth_url, headers={'User-Agent': 'Mozilla/5.0', 'Cache-Control': 'no-cache'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("allowed_hwids", [])
    except Exception as e:
        # 서버 연결 실패 시 보안을 위해 빈 리스트 반환 (차단)
        return []


# ============================================================================
# RVA Offsets for Version 9219
# ============================================================================
VERSION = 9219
CREATE_AUDIO_FRAME_STEREO_INSTRUCTION = 0x116C91
AUDIO_ENCODER_OPUS_CONFIG_SET_CHANNELS_INSTRUCTION = 0x3A0B64
MONO_DOWNMIXER_INSTRUCTIONS = 0xD6319
HIGH_PASS_FILTER_PROCESS = 0x52CF70
EMULATE_STEREO_SUCCESS_1 = 0x520CFB
EMULATE_STEREO_SUCCESS_2 = 0x520D07
EMULATE_BITRATE_MODIFIED = 0x52115A
EMULATE_48KHZ = 0x520E63
HIGHPASS_CUTOFF_FILTER = 0x8D64B0
DC_REJECT = 0x8D6690
DOWNMIX_FUNC = 0x8D2820
AUDIO_ENCODER_OPUS_CONFIG_IS_OK = 0x3A0E00
SETS_BITRATE_BITRATE_VALUE = 0x522F81
SETS_BITRATE_BITWISE_OR = 0x522F89
WEB_RTC_OPUS_SET_BITRATE_CHECK = 0x6A8FA5
THROW_ERROR = 0x2B3340

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# ============================================================================
# PE File Offset Calculation & Shellcode Generators
# ============================================================================
def rva_to_file_offset(file_data: bytearray, rva: int) -> int:
    try:
        dos_header = struct.unpack_from("<I", file_data, 0x3C)[0]
        optional_header_offset = dos_header + 24
        number_of_sections = struct.unpack_from("<H", file_data, dos_header + 6)[0]
        size_of_optional_header = struct.unpack_from("<H", file_data, dos_header + 20)[0]
        section_header_offset = optional_header_offset + size_of_optional_header
        
        for i in range(number_of_sections):
            sec_offset = section_header_offset + (i * 40)
            virtual_address = struct.unpack_from("<I", file_data, sec_offset + 12)[0]
            virtual_size = struct.unpack_from("<I", file_data, sec_offset + 8)[0]
            pointer_to_raw_data = struct.unpack_from("<I", file_data, sec_offset + 20)[0]
            if virtual_address <= rva < virtual_address + virtual_size:
                return rva - virtual_address + pointer_to_raw_data
    except Exception:
        pass
    return rva


def generate_hp_cutoff_shellcode(multiplier: int) -> bytearray:
    multiplier_byte = multiplier & 0xFF
    shellcode = bytearray([
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x53, 0x48, 0x83, 0xEC, 0x28, 0x49, 0x89, 0xCF, 0x41, 0x89, 0xD6,
        0x4D, 0x89, 0xC5, 0x4D, 0x89, 0xCC, 0x44, 0x8B, 0x5D, 0x30, 0x8B, 0x5D, 0x38,
        0x4D, 0x89, 0xE0, 0x49, 0x81, 0xE8, 0x84, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xEA, 0x03, 0x00, 0x00, 0x45, 0x89, 0x88, 0x94, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x89, 0x88, 0xA0, 0x00, 0x00, 0x00,
        0x45, 0x89, 0x88, 0xA4, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9,
        0x45, 0x89, 0x88, 0xB8, 0x00, 0x00, 0x00, 0x41, 0x0F, 0xAF, 0xDB,
        0x85, 0xDB, 0x0F, 0x8E
    ])
    jle_offset_pos = len(shellcode)
    shellcode.extend([0x00, 0x00, 0x00, 0x00])
    shellcode.extend([0x8B, 0x45, 0x38])
    if multiplier >= 0:
        shellcode.extend([0x83, 0xC0, multiplier_byte])
    else:
        abs_multiplier = (-multiplier) & 0xFF
        shellcode.extend([0x83, 0xE8, abs_multiplier])
    shellcode.extend([0xF3, 0x0F, 0x2A, 0xC8, 0x31, 0xC0])
    loop_start = len(shellcode)
    shellcode.extend([
        0xF3, 0x41, 0x0F, 0x10, 0x04, 0x87, 0xF3, 0x0F, 0x59, 0xC1,
        0xF3, 0x41, 0x0F, 0x11, 0x44, 0x85, 0x00, 0x48, 0xFF, 0xC0,
        0x39, 0xD8, 0x7C
    ])
    current_pos = len(shellcode)
    jump_back = (loop_start - current_pos - 1) & 0xFF
    shellcode.append(jump_back)
    end_loop = len(shellcode)
    jle_offset = end_loop - jle_offset_pos - 4
    struct.pack_into("<I", shellcode, jle_offset_pos, jle_offset & 0xFFFFFFFF)
    shellcode.extend([
        0x48, 0x83, 0xC4, 0x28, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
    ])
    while len(shellcode) < 0x100:
        shellcode.append(0x90)
    return shellcode


def generate_dc_reject_shellcode(multiplier: int) -> bytearray:
    multiplier_byte = multiplier & 0xFF
    shellcode = bytearray([
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x53, 0x48, 0x83, 0xEC, 0x20, 0x49, 0x89, 0xCF, 0x49, 0x89, 0xD5,
        0x4D, 0x89, 0xC4, 0x45, 0x89, 0xCE, 0x8B, 0x5D, 0x30,
        0x4D, 0x89, 0xE0, 0x49, 0x81, 0xE8, 0x84, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xEA, 0x03, 0x00, 0x00, 0x45, 0x89, 0x88, 0x94, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x89, 0x88, 0xA0, 0x00, 0x00, 0x00,
        0x45, 0x89, 0x88, 0xA4, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9,
        0x45, 0x89, 0x88, 0xB8, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xAF, 0xF3,
        0x45, 0x85, 0xF6, 0x0F, 0x8E
    ])
    jle_offset_pos = len(shellcode)
    shellcode.extend([0x00, 0x00, 0x00, 0x00])
    shellcode.extend([0x8B, 0x45, 0x30])
    if multiplier >= 0:
        shellcode.extend([0x83, 0xC0, multiplier_byte])
    else:
        abs_multiplier = (-multiplier) & 0xFF
        shellcode.extend([0x83, 0xE8, abs_multiplier])
    shellcode.extend([0xF3, 0x0F, 0x2A, 0xC8, 0x31, 0xC0])
    loop_start = len(shellcode)
    shellcode.extend([
        0xF3, 0x41, 0x0F, 0x10, 0x04, 0x87, 0xF3, 0x0F, 0x59, 0xC1,
        0xF3, 0x41, 0x0F, 0x11, 0x44, 0x85, 0x00, 0x48, 0xFF, 0xC0,
        0x44, 0x39, 0xF0, 0x7C
    ])
    current_pos = len(shellcode)
    jump_back = (loop_start - current_pos - 1) & 0xFF
    shellcode.append(jump_back)
    end_loop = len(shellcode)
    jle_offset = end_loop - jle_offset_pos - 4
    struct.pack_into("<I", shellcode, jle_offset_pos, jle_offset & 0xFFFFFFFF)
    shellcode.extend([
        0x48, 0x83, 0xC4, 0x20, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
    ])
    while len(shellcode) < 0x1B6:
        shellcode.append(0x90)
    return shellcode


# ============================================================================
# Process Management & Utility Logic
# ============================================================================
def close_discord_process(discord_version: str, log_callback):
    exe_map = {"Stable": "Discord.exe", "PTB": "DiscordPTB.exe", "Canary": "DiscordCanary.exe"}
    process_name = exe_map.get(discord_version)
    if not process_name:
        return
    try:
        output = subprocess.check_output(f'tasklist /fi "imagename eq {process_name}"', shell=True, text=True)
        if process_name.lower() in output.lower():
            subprocess.run(f'taskkill /f /im {process_name}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_callback(f"> {discord_version} 프로세스를 종료했습니다.")
        else:
            log_callback(f"> 실행 중인 {discord_version} 프로세스가 없습니다.")
    except Exception as e:
        log_callback(f"> 프로세스 확인/종료 중 오류: {e}")


def start_discord(discord_version: str, log_callback):
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return
    folder_map = {"Stable": "Discord", "PTB": "DiscordPTB", "Canary": "DiscordCanary"}
    exe_map = {"Stable": "Discord.exe", "PTB": "DiscordPTB.exe", "Canary": "DiscordCanary.exe"}
    
    base_dir = os.path.join(local_app_data, folder_map.get(discord_version, "Discord"))
    update_exe = os.path.join(base_dir, "Update.exe")
    process_name = exe_map.get(discord_version, "Discord.exe")
    
    try:
        log_callback(f"> {discord_version} 실행 중...")
        if os.path.exists(update_exe):
            subprocess.Popen([update_exe, "--processStart", process_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_callback(f"> {discord_version} 재시작 완료!")
        else:
            app_dirs = glob.glob(os.path.join(base_dir, "app-*"))
            if app_dirs:
                latest_app = max(app_dirs, key=os.path.getmtime)
                exe_path = os.path.join(latest_app, process_name)
                if os.path.exists(exe_path):
                    subprocess.Popen([exe_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    log_callback(f"> {discord_version} 재시작 완료!")
    except Exception as e:
        log_callback(f"> Discord 자동 실행 실패: {e}")


def is_discord_running(discord_version: str) -> bool:
    exe_map = {"Stable": "Discord.exe", "PTB": "DiscordPTB.exe", "Canary": "DiscordCanary.exe"}
    process_name = exe_map.get(discord_version)
    if not process_name:
        return False
    try:
        output = subprocess.check_output(f'tasklist /fi "imagename eq {process_name}"', shell=True, text=True)
        return process_name.lower() in output.lower()
    except:
        return False


def download_file(url: str, save_path: str, log_callback) -> bool:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(save_path, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
        file_name = os.path.basename(save_path)
        log_callback(f"> 다운로드 완료: {file_name} ({len(data)} bytes)")
        return True
    except Exception as e:
        log_callback(f"> 오류: 파일 다운로드 실패 ({os.path.basename(save_path)}): {e}")
        return False


def apply_voice_node_patches(file_path: str, multiplier: int, log_callback) -> bool:
    log_callback(f"> 코어 패치 적용 중 (통화 끊김 방지, Master 음질 정확도)...")
    try:
        with open(file_path, "rb") as f:
            file_data = bytearray(f.read())
    except Exception as e:
        log_callback(f"> 오류: discord_voice.node 열기 실패: {e}")
        return False
        
    backup_path = file_path + ".backup"
    if not os.path.exists(backup_path):
        try:
            with open(backup_path, "wb") as f:
                f.write(file_data)
            log_callback("> 백업 파일 생성 완료 (.backup)")
        except:
            pass

    def patch(rva, patch_data):
        offset = rva_to_file_offset(file_data, rva)
        if isinstance(patch_data, int):
            file_data[offset] = patch_data
        else:
            file_data[offset:offset+len(patch_data)] = patch_data

    try:
        patch(EMULATE_STEREO_SUCCESS_1, 0x02)
        patch(EMULATE_STEREO_SUCCESS_2, 0xEB)
        patch(CREATE_AUDIO_FRAME_STEREO_INSTRUCTION, bytes([0x49, 0x89, 0xC5, 0x90]))
        patch(AUDIO_ENCODER_OPUS_CONFIG_SET_CHANNELS_INSTRUCTION, 0x02)
        patch(MONO_DOWNMIXER_INSTRUCTIONS, bytes([0x90]*12 + [0xE9]))
        
        patch(EMULATE_BITRATE_MODIFIED, bytes([0x80, 0x0F, 0x08]))
        patch(HIGH_PASS_FILTER_PROCESS, bytes([0x48, 0xB8, 0x10, 0x9E, 0xD8, 0xCF, 0x08, 0x02, 0x00, 0x00, 0xC3]))
        
        hp_code = generate_hp_cutoff_shellcode(multiplier)
        patch(HIGHPASS_CUTOFF_FILTER, hp_code)
        
        dc_code = generate_dc_reject_shellcode(multiplier)
        patch(DC_REJECT, dc_code)
        
        patch(DOWNMIX_FUNC, 0xC3)
        patch(EMULATE_48KHZ, bytes([0x90, 0x90, 0x90]))
        patch(AUDIO_ENCODER_OPUS_CONFIG_IS_OK, bytes([0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3]))
        patch(SETS_BITRATE_BITRATE_VALUE, bytes([0x80, 0x0F, 0x08, 0x00, 0x00]))
        patch(SETS_BITRATE_BITWISE_OR, bytes([0x90, 0x90, 0x90]))
        patch(WEB_RTC_OPUS_SET_BITRATE_CHECK, bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]))
        patch(THROW_ERROR, 0xC3)
        
        with open(file_path, "wb") as f:
            f.write(file_data)
        log_callback("> discord_voice.node 패치가 성공적으로 적용되었습니다!")
        return True
    except Exception as e:
        log_callback(f"> 패치 중 오류 발생: {e}")
        return False


def perform_discord_patch(discord_version: str, multiplier: int, log_callback, completion_callback=None) -> bool:
    log_callback(f"> {discord_version} 패치를 시작합니다...")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        log_callback("> 오류: LocalAppData 경로를 찾을 수 없습니다.")
        return False
        
    folder_map = {"Stable": "Discord", "PTB": "DiscordPTB", "Canary": "DiscordCanary"}
    discord_base = os.path.join(local_app_data, folder_map[discord_version])
    
    if is_discord_running(discord_version):
        log_callback("> Discord 실행 중입니다. 프로세스를 종료합니다...")
        close_discord_process(discord_version, log_callback)
        import time
        time.sleep(1)
        
    app_dirs = glob.glob(os.path.join(discord_base, "app-*"))
    if not app_dirs:
        log_callback("> 오류: Discord 설치 경로를 찾을 수 없습니다.")
        return False
    latest_app_dir = max(app_dirs, key=os.path.getmtime)
    
    voice_modules = glob.glob(os.path.join(latest_app_dir, "modules", "discord_voice-*"))
    if not voice_modules:
        log_callback("> 오류: discord_voice 모듈 폴더를 찾을 수 없습니다.")
        return False
    latest_voice_dir = max(voice_modules, key=os.path.getmtime)
    
    nested_voice_dir = os.path.join(latest_voice_dir, "discord_voice")
    voice_module_directory = nested_voice_dir if os.path.exists(nested_voice_dir) else latest_voice_dir
    
    for item in glob.glob(os.path.join(voice_module_directory, "*")):
        try:
            if os.path.isdir(item):
                import shutil
                shutil.rmtree(item)
            else:
                os.remove(item)
        except:
            pass
            
    required_files = [
        "discord_voice.node", "gpu_encoder_helper.exe", "index.js", "manifest.json",
        "mediapipe.dll", "package.json", "selfie_segmentation.tflite",
        "selfie_segmentation_landscape.tflite"
    ]
    github_base = "https://raw.githubusercontent.com/sh6un/Stereo-Installation-Files/main/NewVoiceModules/"
    for file_name in required_files:
        if not download_file(github_base + file_name, os.path.join(voice_module_directory, file_name), log_callback):
            return False
            
    voice_node_path = os.path.join(voice_module_directory, "discord_voice.node")
    success = apply_voice_node_patches(voice_node_path, multiplier, log_callback)
    
    if success:
        import time
        time.sleep(0.5)
        start_discord(discord_version, log_callback)
        if completion_callback:
            completion_callback()
        
    return success


def restore_discord_patch(discord_version: str, log_callback) -> bool:
    log_callback(f"> {discord_version} 원본 복구를 시작합니다...")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        log_callback("> 오류: LocalAppData 경로를 찾을 수 없습니다.")
        return False
        
    folder_map = {"Stable": "Discord", "PTB": "DiscordPTB", "Canary": "DiscordCanary"}
    discord_base = os.path.join(local_app_data, folder_map[discord_version])
    
    if is_discord_running(discord_version):
        close_discord_process(discord_version, log_callback)
        import time
        time.sleep(1)
        
    app_dirs = glob.glob(os.path.join(discord_base, "app-*"))
    if not app_dirs:
        log_callback("> 오류: Discord 설치 경로를 찾을 수 없습니다.")
        return False
    latest_app_dir = max(app_dirs, key=os.path.getmtime)
    
    voice_modules = glob.glob(os.path.join(latest_app_dir, "modules", "discord_voice-*"))
    if not voice_modules:
        log_callback("> 오류: discord_voice 모듈 폴더를 찾을 수 없습니다.")
        return False
    latest_voice_dir = max(voice_modules, key=os.path.getmtime)
    
    nested_voice_dir = os.path.join(latest_voice_dir, "discord_voice")
    voice_module_directory = nested_voice_dir if os.path.exists(nested_voice_dir) else latest_voice_dir
    
    voice_node_path = os.path.join(voice_module_directory, "discord_voice.node")
    backup_path = voice_node_path + ".backup"
    
    restored = False
    if os.path.exists(backup_path):
        try:
            import shutil
            shutil.copy(backup_path, voice_node_path)
            log_callback("> 백업 파일로부터 원본 discord_voice.node 복구 성공!")
            restored = True
        except Exception as e:
            log_callback(f"> 백업 복구 실패: {e}")
    else:
        log_callback("> 백업 파일을 찾을 수 없습니다. 모듈 폴더를 초기화합니다...")
        try:
            import shutil
            shutil.rmtree(latest_voice_dir)
            log_callback("> 초기화 완료. Discord 재시작 시 깨끗한 파일이 자동으로 다시 받으실 수 있습니다.")
            restored = True
        except Exception as e:
            log_callback(f"> 초기화 실패: {e}")
            
    if restored:
        import time
        time.sleep(0.5)
        start_discord(discord_version, log_callback)
        
    return restored


def set_windows_startup(enable: bool, log_callback):
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "StereoPatcherPython"
    script_path = os.path.abspath(sys.argv[0])
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
    except:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
    try:
        if enable:
            cmd = f'"{sys.executable}" "{script_path}" --auto'
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd)
            log_callback("> [시작 프로그램] 활성화: 윈도우 부팅 시 자동으로 적용됩니다.")
        else:
            try:
                winreg.DeleteValue(key, app_name)
                log_callback("> [시작 프로그램] 비활성화: 시작 프로그램 목록에서 제거되었습니다.")
            except:
                log_callback("> [시작 프로그램] 이미 비활성화 상태입니다.")
        winreg.CloseKey(key)
    except Exception as e:
        log_callback(f"> [시작 프로그램] 설정 실패: {e}")


def check_startup_status() -> bool:
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "StereoPatcherPython"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, app_name)
        winreg.CloseKey(key)
        return True
    except:
        return False


# ============================================================================
# 원격 API 연동 보안 인증 (HWID) GUI 창 클래스
# ============================================================================
class HWIDAuthWindow(ctk.CTk):
    def __init__(self, auto_mode=False):
        super().__init__()
        self.auto_mode = auto_mode
        
        self.title("STEREO PATCHER - 보안 인증")
        self.geometry("420x220")
        self.resizable(False, False)
        
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
        
        self.configure(fg_color="#181a18")
        
        title_lbl = ctk.CTkLabel(self, text="HARDWARE ID VERIFICATION", font=ctk.CTkFont(family="Consolas", size=14, weight="bold"), text_color="#8fa38f")
        title_lbl.place(x=20, y=20)
        
        self.current_hwid = get_hwid()
        self.hwid_entry = ctk.CTkEntry(self, width=380, height=35, fg_color="#121412", border_color="#2c332c", text_color="#8fa38f", font=ctk.CTkFont(family="Consolas", size=11))
        self.hwid_entry.place(x=20, y=60)
        self.hwid_entry.insert(0, self.current_hwid)
        self.hwid_entry.configure(state="readonly")
        
        verify_btn = ctk.CTkButton(self, text="AUTHENTICATE", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), fg_color="#2b422b", hover_color="#365436", text_color="#d4edd4", width=380, height=38, command=self.verify_hwid)
        verify_btn.place(x=20, y=115)
        
        self.authenticated = False

        if self.auto_mode:
            self.after(500, self.verify_hwid)

    def verify_hwid(self):
        # 서버(API)에서 최신 허용 HWID 목록을 불러옴
        authorized_hwids = fetch_authorized_hwids()
        
        if not authorized_hwids:
            messagebox.showerror("인증 오류", "서버와 통신할 수 없거나 인증 목록을 불러오지 못했습니다.")
            self.destroy()
            return

        if self.current_hwid in authorized_hwids:
            self.authenticated = True
            self.destroy()
        else:
            messagebox.showerror(
                "인증 실패",
                f"등록되지 않은 하드웨어(HWID)입니다.\n[현재 HWID: {self.current_hwid}]\n관리자에게 문의하여 HWID를 등록해주세요."
            )


# ============================================================================
# 단일 창 스타일의 모던 패처 앱 클래스 (시작 프로그램 토글 스위치 포함)
# ============================================================================
class StereoPatcherApp(ctk.CTk):
    def __init__(self, auto_mode=False):
        super().__init__()
        self.auto_mode = auto_mode
        
        self.title("Audix Stereo Patcher")
        self.geometry("540x430")
        self.resizable(False, False)
        
        self.configure(fg_color="#181a18")
        
        title_bar = ctk.CTkLabel(self, text="오딕스 스튜디오 스테레오 패치", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#8fa38f")
        title_bar.pack(pady=(12, 6))
        
        # 1. Output Log 박스
        self.log_box = ctk.CTkTextbox(self, width=500, height=130, fg_color="#121412", border_color="#2c332c", border_width=1, text_color="#8fa38f", font=ctk.CTkFont(family="Consolas", size=11), corner_radius=6)
        self.log_box.pack(pady=(0, 15))
        self.log_box.configure(state='disabled')
        
        self.log("구매문의: https://discord.gg/9cSexqkV2G")
        self.log("구매자 아닌 이상 사용 불가")
        self.log("구매: my_only_you")
        
        # 2. 컨트롤 영역 컨테이너 (Destination, Gain Type, Version 가로 정렬)
        ctrl_frame = ctk.CTkFrame(self, fg_color="transparent", width=500, height=60)
        ctrl_frame.pack(pady=(0, 10))
        ctrl_frame.pack_propagate(False)
        
        # Destination (Stable / PTB / Canary)
        lbl_dest = ctk.CTkLabel(ctrl_frame, text="Destination", font=ctk.CTkFont(family="Consolas", size=10), text_color="#738f73")
        lbl_dest.place(x=0, y=0)
        self.dest_var = ctk.StringVar(value="Stable")
        dest_combo = ctk.CTkComboBox(ctrl_frame, values=["Stable", "PTB", "Canary"], variable=self.dest_var, width=150, height=28, fg_color="#121412", border_color="#2c332c", button_color="#2c332c", button_hover_color="#3a473a", text_color="#8fa38f", font=ctk.CTkFont(family="Consolas", size=10))
        dest_combo.place(x=0, y=18)
        
        # Gain Type (Master 고정)
        lbl_gain = ctk.CTkLabel(ctrl_frame, text="Gain Type", font=ctk.CTkFont(family="Consolas", size=10), text_color="#738f73")
        lbl_gain.place(x=175, y=0)
        self.gain_var = ctk.StringVar(value="Stereo")
        gain_combo = ctk.CTkComboBox(ctrl_frame, values=["Stereo"], variable=self.gain_var, width=150, height=28, fg_color="#121412", border_color="#2c332c", button_color="#2c332c", button_hover_color="#3a473a", text_color="#8fa38f", font=ctk.CTkFont(family="Consolas", size=10))
        gain_combo.place(x=175, y=18)
        
        # Version (일반 텍스트 레이블)
        lbl_ver = ctk.CTkLabel(ctrl_frame, text="Version", font=ctk.CTkFont(family="Consolas", size=10), text_color="#738f73")
        lbl_ver.place(x=350, y=0)
        
        ver_val_lbl = ctk.CTkLabel(ctrl_frame, text=f"1.0.{VERSION}", font=ctk.CTkFont(family="Consolas", size=11), text_color="#8fa38f", fg_color="#121412", corner_radius=4, width=150, height=28)
        ver_val_lbl.place(x=350, y=18)
        
        # 4. 부팅 시 자동 적용 (Windows Startup) 토글 스위치 추가
        startup_frame = ctk.CTkFrame(self, fg_color="transparent", width=500, height=30)
        startup_frame.pack(pady=(0, 10))
        startup_frame.pack_propagate(False)
        
        self.startup_var = ctk.BooleanVar(value=check_startup_status())
        startup_chk = ctk.CTkSwitch(startup_frame, text="부팅 시 자동으로 패치 적용 (Windows Startup)", variable=self.startup_var, command=self.on_startup_toggle, font=ctk.CTkFont(family="Consolas", size=11), text_color="#8fa38f", progress_color="#2b422b")
        startup_chk.pack(anchor="w")

        # 3. 하단 버튼 영역 (PATCH 및 RESTORE 버튼)
        btn_frame = ctk.CTkFrame(self, fg_color="transparent", width=500, height=36)
        btn_frame.pack()
        btn_frame.pack_propagate(False)
        
        patch_btn = ctk.CTkButton(btn_frame, text="PATCH", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), fg_color="#2b422b", hover_color="#365436", text_color="#d4edd4", width=242, height=36, command=self.on_patch_click)
        patch_btn.place(x=0, y=0)
        
        restore_btn = ctk.CTkButton(btn_frame, text="RESTORE", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), fg_color="#222822", hover_color="#2c332c", text_color="#9ab39a", width=242, height=36, command=self.on_restore_click)
        restore_btn.place(x=258, y=0)
        
        if self.auto_mode:
            self.after(800, self.on_patch_click)

    def log(self, message):
        self.log_box.configure(state='normal')
        self.log_box.insert(ctk.END, message + "\n")
        self.log_box.see(ctk.END)
        self.log_box.configure(state='disabled')

    def on_patch_click(self):
        discord_ver = self.dest_var.get()
        multiplier = -1  # Master 등급 고정 배율
        
        self.log_box.configure(state='normal')
        self.log_box.delete("1.0", ctk.END)
        self.log_box.configure(state='disabled')
        
        def on_complete():
            self.log("> Patch completed successfully.")
            self.log("> Closing application...")
            self.after(1200, self.destroy)

        threading.Thread(target=perform_discord_patch, args=(discord_ver, multiplier, self.log, on_complete), daemon=True).star()

    def on_restore_click(self):
        discord_ver = self.dest_var.get()
        
        self.log_box.configure(state='normal')
        self.log_box.delete("1.0", ctk.END)
        self.log_box.configure(state='disabled')
        
        threading.Thread(target=restore_discord_patch, args=(discord_ver, self.log), daemon=True).start()

    def on_startup_toggle(self):
        enable = self.startup_var.get()
        set_windows_startup(enable, self.log)


# ============================================================================
# 단일 인스턴스(중복 실행) 방지용 뮤텍스 체크
# ============================================================================
def check_single_instance(mutex_name="Global\\AudixStereoPatcherMutex"):
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, mutex_name)
    if kernel32.GetLastError() == 183:
        return False
    return True


if __name__ == "__main__":
    if not check_single_instance():
        sys.exit(0)
        
    auto_mode = len(sys.argv) > 1 and sys.argv[1] == "--auto"
    
    auth_win = HWIDAuthWindow(auto_mode=auto_mode)
    auth_win.mainloop()
    
    if getattr(auth_win, "authenticated", False):
        app = StereoPatcherApp(auto_mode=auto_mode)
        app.mainloop()