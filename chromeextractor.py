import sqlite3
import base64
import json
import os
import time
import shutil
from Crypto.Cipher import AES
import win32crypt
import psutil
import ctypes
import traceback

def get_desktop_path():
    """Detecta a pasta 'Desktop' no sistema."""
    print("[DEBUG] Obtendo o caminho da área de trabalho.")
    csidl_desktop = 0x0010
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.shell32.SHGetFolderPathW(0, csidl_desktop, 0, 0, buf)
    return buf.value

OUTPUT_FILE_PATH = os.path.join(get_desktop_path(), "ChromePasswords.txt")
TEMP_DB_FILE = "temp_ChromePasswords.db"

def get_profile_name(profile_path):
    """Obtém o nome do perfil a partir do arquivo 'Preferences'."""
    print(f"[DEBUG] Obtendo o nome do perfil para '{profile_path}'")
    preferences_path = os.path.join(profile_path, "Preferences")
    
    try:
        with open(preferences_path, "r", encoding="utf-8") as f:
            preferences = json.load(f)
            profile_name = preferences.get("profile", {}).get("name", "Perfil Desconhecido")
            return profile_name
    except FileNotFoundError:
        print(f"[WARNING] Arquivo 'Preferences' não encontrado no caminho '{preferences_path}'")
        return "Perfil Desconhecido"
    except json.JSONDecodeError as json_error:
        print(f"[ERROR] Erro ao decodificar JSON do arquivo 'Preferences': {json_error}")
        return "Perfil Desconhecido"

def get_key(keypath):
    """Obtém a chave de criptografia do arquivo 'Local State' do Chrome."""
    print(f"[DEBUG] Obtendo a chave de criptografia do arquivo '{keypath}'")
    try:
        if not os.path.exists(keypath):
            raise FileNotFoundError(f"O arquivo '{keypath}' não foi encontrado.")

        with open(keypath, "r", encoding="utf-8") as f:
            local_state_data = json.load(f)
        
        encrypted_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])
        encryption_key = win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]

        if encryption_key:
            print("[DEBUG] Chave de criptografia obtida com sucesso.")
            return encryption_key
        else:
            raise ValueError("Chave de criptografia não encontrada.")
    except FileNotFoundError as fnf_error:
        print(f"[ERROR] {fnf_error}")
    except json.JSONDecodeError as json_error:
        print(f"[ERROR] Erro ao decodificar JSON: {json_error}")
    except Exception as e:
        print(f"[ERROR] Erro ao obter a chave: {e}")
        traceback.print_exc()
    return None

def password_decryption(password, encryption_key):
    """Descriptografar a senha usando a chave fornecida."""
    print("[DEBUG] Descriptografando a senha")
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except Exception as e:
        print(f"[DEBUG] Falha com AES GCM: {e}")
        try:
            iv = password[:16]
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted_password = cipher.decrypt(password[16:])
            return decrypted_password.rstrip(b"\x00").decode()
        except Exception as e:
            print(f"[DEBUG] Falha com AES CBC: {e}")
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except Exception as e:
                print(f"[ERROR] Erro na descriptografia alternativa: {e}")
                traceback.print_exc()
    return "Sem senhas"

def close_chrome():
    """Força o fechamento de todos os processos do Chrome."""
    print("[DEBUG] Forçando o fechamento dos processos do Chrome")
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'chrome.exe':
            try:
                proc.kill()
                print(f"[DEBUG] Processo {proc.info['pid']} encerrado.")
            except psutil.NoSuchProcess:
                print(f"[WARNING] Processo {proc.info['pid']} não encontrado.")
            except psutil.AccessDenied:
                print(f"[ERROR] Acesso negado ao processo {proc.info['pid']}.")

def remove_temp_file():
    """Remove o arquivo temporário com várias tentativas se necessário."""
    print("[DEBUG] Removendo o arquivo temporário")
    attempts = 0
    while attempts < 5:
        try:
            if os.path.exists(TEMP_DB_FILE):
                os.remove(TEMP_DB_FILE)
                print("[DEBUG] Arquivo temporário removido com sucesso.")
            break
        except Exception as e:
            print(f"[ERROR] Erro ao remover arquivo temporário na tentativa {attempts+1}: {e}")
            attempts += 1
            time.sleep(2)

def get_credt(dbpath, keypath, profile_name):
    """Extrai credenciais do banco de dados e escreve em um arquivo txt."""
    print(f"[DEBUG] Extraindo credenciais do banco de dados '{dbpath}'")
    credentials_found = False
    collected_info = []
    try:
        if not os.path.exists(dbpath):
            raise FileNotFoundError(f"O arquivo do banco de dados '{dbpath}' não foi encontrado.")

        close_chrome()
        time.sleep(5)
        
        if os.path.exists(TEMP_DB_FILE):
            os.remove(TEMP_DB_FILE)
        shutil.copyfile(dbpath, TEMP_DB_FILE)
        time.sleep(5)
        
        with sqlite3.connect(TEMP_DB_FILE) as db:
            cursor = db.cursor()
            cursor.execute("PRAGMA busy_timeout = 5000;")
            cursor.execute(
                "SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_last_used"
            )
            for row in cursor.fetchall():
                main_url, login_page_url, user_name, password, date_created, last_used = row
                decrypted_password = password_decryption(password, get_key(keypath))
                if user_name or decrypted_password:
                    credentials_found = True
                    info = (f"Perfil: {profile_name}\n"
                            f"URL Principal: {main_url}\n"
                            f"URL de Login: {login_page_url}\n"
                            f"Nome de usuário: {user_name}\n"
                            f"Senha descriptografada: {decrypted_password}\n")
                    collected_info.append(info)
            cursor.close()
        db.close()
    except FileNotFoundError as fnf_error:
        print(f"[ERROR] {fnf_error}")
    except sqlite3.OperationalError as sql_error:
        print(f"[ERROR] Erro operacional do SQLite: {sql_error}")
    except Exception as e:
        print(f"[ERROR] Erro inesperado: {e}")
        traceback.print_exc()
    finally:
        remove_temp_file()
        if not credentials_found:
            collected_info.append(f"Perfil: {profile_name}\nNenhuma senha ou login encontrado.\n")
    return collected_info

def process_profiles():
    """Processa todos os perfis do Chrome para extrair credenciais."""
    print("[DEBUG] Iniciando o processamento dos perfis do Chrome")
    root_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
    if not os.path.exists(root_path):
        print(f"[ERROR] O diretório de perfis do Chrome '{root_path}' não foi encontrado.")
        return

    profiles = [i for i in os.listdir(root_path) if i.startswith("Profile") or i == "Default"]

    if not profiles:
        print("[WARNING] Nenhum perfil encontrado no diretório do Chrome.")

    all_credentials_info = []

    for profile in profiles:
        profile_path = os.path.join(root_path, profile)
        profile_name = get_profile_name(profile_path)
        print(f"[DEBUG] Processando dados do perfil '{profile}' ({profile_name})")
        db_path = os.path.join(profile_path, "Login Data")
        key_path = os.path.join(root_path, "Local State")
        profile_credentials_info = get_credt(db_path, key_path, profile_name)
        all_credentials_info.extend(profile_credentials_info)
        print(f"[DEBUG] Sucesso para o perfil '{profile}' ({profile_name})")

    if all_credentials_info:
        try:
            with open(OUTPUT_FILE_PATH, "w") as f:
                f.write("\n".join(all_credentials_info))
            print(f"[DEBUG] Extração de dados concluída. Verifique o arquivo na sua Área de Trabalho.")
        except Exception as e:
            print(f"[ERROR] Erro ao criar o arquivo de saída: {e}")
            traceback.print_exc()
    else:
        print(f"[DEBUG] Arquivo não criado. Verifique por erros.")

try:
    process_profiles()
except Exception as e:
    print(f"[ERROR] Erro encontrado durante o processamento: {e}")
    traceback.print_exc()

input("Pressione Enter para sair...")

