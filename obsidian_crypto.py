import os
import sys
import base64
import json
import getpass
import secrets
import threading
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from kyber_py.ml_kem import ML_KEM_768

MAGIC_HEADER = b'VAULTRSA_v1\n'
MLKEM_MAGIC = b'VAULTMLKEM768_v1\n'
MLKEM_PRIV_MAGIC = b'MLKEM768_PRIV_v1\n'
MLKEM_PRIV_ENC_MAGIC = b'MLKEM768_PRIV_ENC_v1\n'
MANIFEST_FILE = '.vault_manifest'
IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp'}

GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def progress_bar(current: int, total: int, width: int = 35):
    if total == 0:
        return
    percent = current / total
    filled = int(width * percent)
    bar = '#' * filled + '-' * (width - filled)
    sys.stdout.write(f'\r  [{bar}] {int(percent*100)}% ({current}/{total})')
    sys.stdout.flush()
    if current == total:
        print()

def get_config_path():
    return os.path.join(script_dir, 'config.json')

def get_xor_key_path():
    config = load_config()
    path = config.get('xor_key', '').strip()
    if path:
        if os.path.isdir(path):
            return os.path.join(path, 'xor_key.bin')
        return path
    return os.path.join(script_dir, 'xor_key.bin')

DEFAULT_CONFIG = {
    'brain_folder': '',
    'private_key': '',
    'public_key': '',
    'xor_key': '',
    'mlkem_private_key': '',
    'mlkem_public_key': '',
}

def load_config():
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(get_config_path()):
        with open(get_config_path(), 'r') as f:
            stored = json.load(f)
            cfg.update(stored)
    return cfg

def save_config(config):
    with open(get_config_path(), 'w') as f:
        json.dump(config, f, indent=2)

def shorten_path(path, max_len=35):
    if len(path) <= max_len:
        return path
    return '...' + path[-(max_len-3):]

def get_brain_folder():
    config = load_config()
    folder = config.get('brain_folder', '').strip()
    if folder and os.path.isdir(folder):
        return folder
    for guess in [os.path.join(script_dir, 'Brain'), script_dir]:
        if os.path.isdir(guess):
            return guess
    return script_dir

def get_key_paths():
    config = load_config()
    priv = config.get('private_key', '').strip()
    pub = config.get('public_key', '').strip()
    if priv and pub:
        return priv, pub
    return os.path.join(script_dir, 'private_key.pem'), os.path.join(script_dir, 'public_key.pem')

def get_mlkem_key_paths():
    config = load_config()
    priv = config.get('mlkem_private_key', '').strip()
    pub = config.get('mlkem_public_key', '').strip()
    if priv and pub:
        return priv, pub
    rsa_priv = config.get('private_key', '').strip()
    folder = os.path.dirname(rsa_priv) if rsa_priv else script_dir
    return os.path.join(folder, 'mlkem_private_key.bin'), os.path.join(folder, 'mlkem_public_key.bin')

PQC_LABEL = 'ML-KEM-768'
PQC_BADGE = c('(POST-QUANTUM SAFE)', BOLD + GREEN)

def get_rel_paths(root_folder):
    paths = []
    for root, dirs, files in os.walk(root_folder):
        dirs[:] = [d for d in dirs if d != '.obsidian']
        for file in files:
            if file == MANIFEST_FILE:
                continue
            ext = os.path.splitext(file)[1].lower()
            if ext == '.md' or ext in IMAGE_EXTS:
                rel = os.path.relpath(os.path.join(root, file), root_folder)
                paths.append(rel)
    return paths

def is_content_encrypted(file_path):
    try:
        with open(file_path, 'rb') as f:
            head = f.read(32)
        return head.startswith(MAGIC_HEADER) or head.startswith(MLKEM_MAGIC)
    except:
        return False

def get_manifest_mode(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(32)
    except Exception:
        return None
    if head.startswith(MLKEM_MAGIC):
        return 'ml-kem-768'
    if head.startswith(MAGIC_HEADER):
        return 'rsa-4096'
    return None

def load_xor_key():
    path = get_xor_key_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(c(f"\n  Error reading XOR key: {e}", RED))
        return None

def save_xor_key(key):
    path = get_xor_key_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(key)

def xor_encrypt_name(rel_path: str) -> str:
    key = load_xor_key()
    if key is None:
        raise RuntimeError("XOR key not found. Generate one in Config > XOR Key.")
    parts = rel_path.split(os.sep)
    enc_parts = []
    for part in parts:
        data = part.encode('utf-8')
        raw = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        enc_parts.append(base64.urlsafe_b64encode(raw).decode('ascii').rstrip('='))
    return '/'.join(enc_parts)

def xor_decrypt_name(enc_path: str) -> str:
    key = load_xor_key()
    if key is None:
        raise RuntimeError("XOR key not found. Generate one in Config > XOR Key.")
    parts = enc_path.split('/')
    dec_parts = []
    for part in parts:
        padded = part + '=' * (-len(part) % 4)
        data = base64.urlsafe_b64decode(padded)
        raw = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        dec_parts.append(raw.decode('utf-8'))
    return os.sep.join(dec_parts)

# ── HYBRID ENCRYPTION (AES-256-GCM + ML-KEM-768, POST-QUANTUM) ──

AES_KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

# ── LEGACY (RSA-4096 + AES-256-GCM) — only used to decrypt old vaults ──

def hybrid_encrypt(plaintext: bytes, pub_key) -> bytes:
    aes_key = secrets.token_bytes(AES_KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    enc_key = pub_key.encrypt(aes_key, padding.PKCS1v15())
    enc_key_len = len(enc_key).to_bytes(2, 'big')
    return enc_key_len + enc_key + nonce + tag + ciphertext

def hybrid_decrypt(data: bytes, priv_key) -> bytes:
    enc_key_len = int.from_bytes(data[:2], 'big')
    enc_key = data[2:2+enc_key_len]
    nonce = data[2+enc_key_len:2+enc_key_len+NONCE_LEN]
    tag = data[2+enc_key_len+NONCE_LEN:2+enc_key_len+NONCE_LEN+TAG_LEN]
    ciphertext = data[2+enc_key_len+NONCE_LEN+TAG_LEN:]
    aes_key = priv_key.decrypt(enc_key, padding.PKCS1v15())
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ── ML-KEM-768 HYBRID ENCRYPTION ──

def mlkem_hybrid_encrypt(plaintext: bytes, ek: bytes) -> bytes:
    shared, kem_ct = ML_KEM_768.encaps(ek)
    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = Cipher(algorithms.AES(shared), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return len(kem_ct).to_bytes(2, 'big') + kem_ct + nonce + tag + ciphertext

def mlkem_hybrid_decrypt(data: bytes, dk: bytes) -> bytes:
    kem_ct_len = int.from_bytes(data[:2], 'big')
    kem_ct = data[2:2+kem_ct_len]
    shared = ML_KEM_768.decaps(dk, kem_ct)
    nonce = data[2+kem_ct_len:2+kem_ct_len+NONCE_LEN]
    tag = data[2+kem_ct_len+NONCE_LEN:2+kem_ct_len+NONCE_LEN+TAG_LEN]
    ciphertext = data[2+kem_ct_len+NONCE_LEN+TAG_LEN:]
    cipher = Cipher(algorithms.AES(shared), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def save_mlkem_private_key(dk: bytes, path: str, password: str = ''):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if password:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(NONCE_LEN)
        kdf = Scrypt(salt=salt, length=AES_KEY_LEN, n=2**14, r=8, p=1)
        key = kdf.derive(password.encode('utf-8'))
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        wrapped = encryptor.update(dk) + encryptor.finalize()
        payload = MLKEM_PRIV_ENC_MAGIC + salt + nonce + encryptor.tag + wrapped
    else:
        payload = MLKEM_PRIV_MAGIC + dk
    with open(path, 'wb') as f:
        f.write(payload)

def read_mlkem_private_key(path: str, password: str = '') -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    if data.startswith(MLKEM_PRIV_ENC_MAGIC):
        body = data[len(MLKEM_PRIV_ENC_MAGIC):]
        salt = body[:16]
        nonce = body[16:16+NONCE_LEN]
        tag = body[16+NONCE_LEN:16+NONCE_LEN+TAG_LEN]
        wrapped = body[16+NONCE_LEN+TAG_LEN:]
        kdf = Scrypt(salt=salt, length=AES_KEY_LEN, n=2**14, r=8, p=1)
        key = kdf.derive(password.encode('utf-8'))
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(wrapped) + decryptor.finalize()
    if data.startswith(MLKEM_PRIV_MAGIC):
        return data[len(MLKEM_PRIV_MAGIC):]
    raise RuntimeError("Not an ML-KEM-768 private key file")

# ── UI ──────────────────────────────────────────

def show_menu():
    clear()
    config = load_config()
    bf = config.get('brain_folder', '') or '(not set)'
    kf = config.get('private_key', '') or '(not set)'
    xor_ok = os.path.exists(get_xor_key_path())

    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("       OBSIDIAN VAULT CRYPTO TOOL", BOLD + CYAN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    print(c("   What would you like to do?\n", YELLOW))
    print(f"   {c('[1]', CYAN)} {c('Encrypt', BOLD)}")
    print(f"   {c('[2]', CYAN)} {c('Decrypt', BOLD)}")
    print(f"   {c('[3]', CYAN)} {c('Config', BOLD)}")
    print(f"   {c('[4]', CYAN)} Exit\n")
    print(f"{BOLD}+{'-'*48}+{RESET}")
    print(f"   {c('Brain folder:', CYAN)} {shorten_path(bf)}")
    print(f"   {c('Keys folder:', CYAN)} {shorten_path(os.path.dirname(kf) if kf and kf != '(not set)' else '(not set)')}")
    print(f"   {c('XOR key:', CYAN)}      {shorten_path(get_xor_key_path())} {c('[OK]', GREEN) if xor_ok else c('[MISSING]', RED)}")
    print(f"   {c('Encryption:', CYAN)}    {PQC_LABEL} {PQC_BADGE}")
    idle_txt = 'n/a'
    if _watch_state['checked']:
        if _watch_state['last_change']:
            idle_txt = f"{int((time.time() - _watch_state['last_change']) / 60)}m"
        else:
            idle_txt = 'scanning'
    print(f"   {c('Auto-encrypt:', CYAN)}  after {AUTO_ENCRYPT_IDLE_MINUTES}m idle w/ key drive (idle: {idle_txt})")
    print(f"{BOLD}+{'-'*48}+{RESET}\n")

def show_config():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           CONFIGURATION", BOLD + MAGENTA))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    config = load_config()

    xor_path = get_xor_key_path()
    xor_ok = os.path.exists(xor_path)
    xor_size = os.path.getsize(xor_path) if xor_ok else 0

    print(c("  Current Settings:\n", YELLOW))
    print(f"  {c('Brain folder:', CYAN)}     {config.get('brain_folder') or '(not set)'}")
    mlk_priv, mlk_pub = get_mlkem_key_paths()
    print(f"  {c('ML-KEM private:', CYAN)}   {mlk_priv}")
    print(f"  {c('ML-KEM public:', CYAN)}    {mlk_pub} {c('[OK]', GREEN) if os.path.exists(mlk_pub) else c('[MISSING]', RED)}")
    print(f"  {c('XOR key:', CYAN)}          {xor_path} ({xor_size} bytes)")
    print(f"  {c('Encryption:', CYAN)}       {PQC_LABEL} {PQC_BADGE}")
    print(f"\n{BOLD}+{'-'*48}+{RESET}\n")
    print(c("  What would you like to configure?\n", YELLOW))
    print(f"  {c('[1]', CYAN)} Set Brain folder path")
    print(f"  {c('[2]', CYAN)} Set Keys folder path")
    print(f"  {c('[3]', CYAN)} Set XOR key path")
    print(f"  {c('[4]', CYAN)} Generate new ML-KEM-768 keys (Post-Quantum Safe)")
    print(f"  {c('[5]', CYAN)} Generate new XOR key (for filenames)")
    print(f"  {c('[6]', CYAN)} Reset to defaults")
    print(f"  {c('[7]', CYAN)} Back to main menu\n")
    choice = input(f"  {c('Enter choice', YELLOW)} ({c('1-7', CYAN)}): ").strip()
    if choice == '1':
        set_brain_folder(config)
    elif choice == '2':
        set_keys_folder(config)
    elif choice == '3':
        set_xor_key_path(config)
    elif choice == '4':
        generate_mlkem_keys()
    elif choice == '5':
        generate_xor_key()
    elif choice == '6':
        reset_config()
    elif choice == '7':
        return
    else:
        print(c("\n  Invalid choice.", RED))
        input("  Press Enter to continue...")

def set_brain_folder(config):
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("         SET BRAIN FOLDER", BOLD + CYAN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    print(f"  Current: {config.get('brain_folder') or '(not set)'}\n")
    print(c("  Enter the full path to your Brain folder\n", YELLOW))
    path = input("  Path: ").strip()
    if path:
        if os.path.isdir(path):
            config['brain_folder'] = os.path.abspath(path)
            save_config(config)
            print(c("\n  Brain folder set successfully!", GREEN))
        else:
            create = input(c("\n  Folder doesn't exist. Create it? (y/N): ", RED)).strip().lower()
            if create == 'y':
                os.makedirs(path, exist_ok=True)
                config['brain_folder'] = os.path.abspath(path)
                save_config(config)
                print(c("\n  Folder created and set!", GREEN))
            else:
                print(c("\n  Setting not saved.", YELLOW))
    else:
        config['brain_folder'] = ''
        save_config(config)
        print(c("\n  Brain folder cleared.", GREEN))
    input("\n  Press Enter to return to config...")

def set_keys_folder(config):
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("         SET KEYS FOLDER", BOLD + CYAN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    cur = os.path.dirname(config.get('private_key', '')) or ''
    print(f"  Current: {cur or '(not set - using app folder)'}\n")
    print(c("  Enter the folder where your keys are stored\n", YELLOW))
    print(f"  Leave blank to use the app folder\n")
    path = input("  Folder: ").strip()
    if path:
        folder = os.path.abspath(path)
        os.makedirs(folder, exist_ok=True)
        config['private_key'] = os.path.join(folder, 'private_key.pem')
        config['public_key'] = os.path.join(folder, 'public_key.pem')
        config['mlkem_private_key'] = os.path.join(folder, 'mlkem_private_key.bin')
        config['mlkem_public_key'] = os.path.join(folder, 'mlkem_public_key.bin')
    else:
        config['private_key'] = os.path.join(script_dir, 'private_key.pem')
        config['public_key'] = os.path.join(script_dir, 'public_key.pem')
        config['mlkem_private_key'] = os.path.join(script_dir, 'mlkem_private_key.bin')
        config['mlkem_public_key'] = os.path.join(script_dir, 'mlkem_public_key.bin')
    save_config(config)
    if os.path.exists(config['mlkem_public_key']):
        print(c("\n  ML-KEM-768 keys found in this folder!", GREEN))
    else:
        print(c("\n  No ML-KEM-768 keys found in this folder yet.", YELLOW))
        gen = input("  Generate new ML-KEM-768 keys now? (Y/n): ").strip().lower()
        if gen != 'n':
            generate_mlkem_keys()
            return
    input("\n  Press Enter to return to config...")

def set_xor_key_path(config):
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("         SET XOR KEY PATH", BOLD + CYAN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    cur = get_xor_key_path()
    print(f"  Current: {cur}\n")
    print(c("  Enter the full path to xor_key.bin\n", YELLOW))
    print(f"  Leave blank to use the default (app folder)\n")
    path = input("  Path: ").strip()
    if path:
        full = os.path.abspath(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        config['xor_key'] = full
    else:
        config['xor_key'] = ''
    save_config(config)
    new_path = get_xor_key_path()
    if os.path.exists(new_path):
        print(c("\n  XOR key found at this path!", GREEN))
    else:
        print(c("\n  Path set. No key file exists there yet.", YELLOW))
        gen = input("  Generate a new XOR key now? (Y/n): ").strip().lower()
        if gen != 'n':
            generate_xor_key()
            return
    input("\n  Press Enter to return to config...")

def generate_xor_key():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("         XOR KEY GENERATION", BOLD + CYAN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    xor_path = get_xor_key_path()
    if os.path.exists(xor_path):
        print(c("  XOR key already exists!\n", YELLOW))
        print(f"  Path: {xor_path}\n")
        if input("  Overwrite? (y/N): ").strip().lower() != 'y':
            print(c("\n  Cancelled.\n", YELLOW))
            input("  Press Enter to return...")
            return
    print(c("  Generating 32-byte XOR key...\n", YELLOW))
    key = secrets.token_bytes(32)
    save_xor_key(key)
    print(c("  XOR key generated and saved!", GREEN))
    print(f"  Path: {xor_path} ({len(key)} bytes)\n")
    input("  Press Enter to return...")

def generate_mlkem_keys():
    config = load_config()
    priv, pub = get_mlkem_key_paths()
    if os.path.exists(priv):
        clear()
        print(f"\n{BOLD}+{'='*48}+{RESET}")
        print(c("       ML-KEM-768 KEY GENERATION", BOLD + MAGENTA))
        print(f"{BOLD}+{'='*48}+{RESET}\n")
        print(c("  ML-KEM-768 keys already exist!\n", YELLOW))
        print(f"  Private: {priv}")
        print(f"  Public:  {pub}\n")
        if input("  Overwrite? (y/N): ").strip().lower() != 'y':
            print(c("\n  Cancelled.\n", YELLOW))
            input("  Press Enter to return...")
            return
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("       ML-KEM-768 KEY GENERATION", BOLD + MAGENTA))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    print(c("  ML-KEM-768 - NIST Post-Quantum standard (FIPS 203)", CYAN))
    print(c("  POST-QUANTUM SAFE", BOLD + GREEN))
    print(c("  Generating ML-KEM-768 keypair...\n", YELLOW))
    ek, dk = ML_KEM_768.keygen()
    password = getpass.getpass("  Enter password to protect private key\n  (press Enter for none): ")
    save_mlkem_private_key(dk, priv, password)
    os.makedirs(os.path.dirname(pub), exist_ok=True)
    with open(pub, 'wb') as f:
        f.write(ek)
    print(c("\n  Keys generated successfully!", GREEN))
    print(f"\n  {c(os.path.basename(priv), BOLD)}  <- {c('KEEP THIS SECRET!', RED)}")
    print(f"  {c(os.path.basename(pub), BOLD)}   <- {c('Safe to share', CYAN)}")
    print(c("\n  ML-KEM-768 is resistant to quantum computer attacks.", CYAN))
    input("\n  Press Enter to continue...")

def reset_config():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           RESET CONFIG", BOLD + YELLOW))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    if input("  Reset all settings to defaults? (y/N): ").strip().lower() == 'y':
        save_config(dict(DEFAULT_CONFIG))
        print(c("\n  Config reset to defaults.", GREEN))
        input("  Press Enter to continue...")

# ── WATCHDOG (AUTO-ENCRYPT AFTER IDLE) ──────────

AUTO_ENCRYPT_IDLE_MINUTES = 30
AUTO_ENCRYPT_POLL_SECONDS = 15
_enc_lock = threading.Lock()
_watch_state = {'last_change': 0.0, 'checked': False}

def key_drive_available():
    mlk_priv, mlk_pub = get_mlkem_key_paths()
    drive = os.path.splitdrive(mlk_pub)[0]
    if not drive or not os.path.exists(drive + os.sep):
        return False
    if not os.path.exists(mlk_pub):
        return False
    if not os.path.exists(get_xor_key_path()):
        return False
    return True

def vault_last_change():
    brain_folder = get_brain_folder()
    if not os.path.isdir(brain_folder):
        return None
    latest = 0.0
    for root, dirs, files in os.walk(brain_folder):
        dirs[:] = [d for d in dirs if d != '.obsidian']
        for f in files:
            if f == MANIFEST_FILE:
                continue
            try:
                mt = os.path.getmtime(os.path.join(root, f))
            except OSError:
                continue
            if mt > latest:
                latest = mt
    return latest or None

def auto_encrypt_eligible(mt=None):
    if not key_drive_available():
        return False, 'key drive not available'
    brain_folder = get_brain_folder()
    if os.path.exists(os.path.join(brain_folder, MANIFEST_FILE)):
        return False, 'already encrypted'
    if mt is None:
        mt = vault_last_change()
    if mt is None:
        return False, 'no files to encrypt'
    idle = time.time() - mt
    if idle < AUTO_ENCRYPT_IDLE_MINUTES * 60:
        return False, f'idle {int(idle/60)}m of {AUTO_ENCRYPT_IDLE_MINUTES}m'
    return True, f'ready (idle {int(idle/60)}m)'

def watchdog_loop():
    while True:
        try:
            mt = vault_last_change()
            _watch_state['last_change'] = mt or 0.0
            _watch_state['checked'] = True
            if mt is None:
                time.sleep(AUTO_ENCRYPT_POLL_SECONDS)
                continue
            ok, reason = auto_encrypt_eligible(mt)
            if ok:
                print(c(f"\n  [WATCHDOG] Key drive plugged in, vault idle >= {AUTO_ENCRYPT_IDLE_MINUTES} min - encrypting...", CYAN))
                if _enc_lock.acquire(blocking=False):
                    try:
                        run_encrypt(interactive=False)
                    finally:
                        _enc_lock.release()
                    time.sleep(60)
        except Exception as e:
            print(c(f"\n  [WATCHDOG] error: {e}", RED))
        time.sleep(AUTO_ENCRYPT_POLL_SECONDS)

# ── ENCRYPT ─────────────────────────────────────

def encrypt_vault():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           ENCRYPT MODE", BOLD + GREEN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    run_encrypt(interactive=True)

def run_encrypt(interactive=True):
    print(f"  {c('Encryption method:', CYAN)} {PQC_LABEL} {PQC_BADGE}\n")

    brain_folder = get_brain_folder()

    if not os.path.exists(brain_folder):
        print(c(f"  Brain folder not found: {brain_folder}", RED))
        print(c("  Go to Config > Set Brain folder to fix this.\n", YELLOW))
        if interactive:
            input("  Press Enter to return to menu...")
        return False
    if not os.path.exists(get_xor_key_path()):
        print(c("  XOR key not found!", RED))
        print(c("  Go to Config > Generate new XOR key first.\n", YELLOW))
        if interactive:
            input("  Press Enter to return to menu...")
        return False

    manifest_path = os.path.join(brain_folder, MANIFEST_FILE)
    existing_mode = get_manifest_mode(manifest_path)
    if existing_mode and existing_mode != 'ml-kem-768':
        print(c("\n  This vault was encrypted with RSA-4096 (legacy).", RED))
        print(c("  Decrypt it first to convert it to ML-KEM-768.\n", YELLOW))
        if interactive:
            input("  Press Enter to return to menu...")
        return False

    print(c("  Loading ML-KEM-768 public key...", YELLOW))
    mlk_priv_file, mlk_pub_file = get_mlkem_key_paths()
    if not os.path.exists(mlk_pub_file):
        print(c("  ML-KEM-768 public key not found!", RED))
        print(f"  Expected: {mlk_pub_file}\n" + c("  Go to Config > Generate new ML-KEM-768 keys.\n", YELLOW))
        if interactive:
            input("  Press Enter to return to menu...")
        return False
    with open(mlk_pub_file, 'rb') as f:
        public_key = f.read()
    print(c("  Public key loaded\n", GREEN))

    rel_paths = get_rel_paths(brain_folder)
    print(c(f"  Found {len(rel_paths)} file(s)\n", YELLOW))
    if not rel_paths:
        print(c("  No files to encrypt.\n", GREEN))
        if interactive:
            input("  Press Enter to return to menu...")
        return False

    manifest_files = {}
    print(c("  +---------------------------------------------+", CYAN))
    print(c("    ENCRYPTING", BOLD))
    print(c("  +---------------------------------------------+", CYAN))

    encrypted_count = 0
    for i, rel in enumerate(rel_paths, 1):
        full = os.path.join(brain_folder, rel)
        try:
            if is_content_encrypted(full):
                progress_bar(i, len(rel_paths))
                continue
        except:
            pass

        try:
            parent_rel = os.path.dirname(rel).replace(os.sep, '/')
            enc_name = xor_encrypt_name(os.path.basename(rel))
            safe_name = f"{parent_rel}/{enc_name}" if parent_rel else enc_name
            safe_filename = enc_name

            with open(full, 'rb') as f:
                content = f.read()
            enc_data = mlkem_hybrid_encrypt(content, public_key)

            parent_dir = os.path.dirname(full)
            new_full = os.path.join(parent_dir, safe_filename)
            with open(new_full, 'wb') as f:
                f.write(MLKEM_MAGIC + base64.b64encode(enc_data))

            os.remove(full)

            manifest_files[safe_name] = rel
            encrypted_count += 1
        except Exception as e:
            print(c(f"\n  Error encrypting {rel}: {e}", RED))
        progress_bar(i, len(rel_paths))

    manifest = {'files': manifest_files}
    manifest_bytes = json.dumps(manifest, indent=2).encode('utf-8')
    enc_manifest = mlkem_hybrid_encrypt(manifest_bytes, public_key)
    with open(manifest_path, 'wb') as f:
        f.write(MLKEM_MAGIC + base64.b64encode(enc_manifest))

    print()
    print(c("  +---------------------------------------------+", CYAN))
    print(f"  {c('[OK]', GREEN)} {c('Encrypted:', BOLD)} {encrypted_count}  {c('Files with XOR-encrypted names', BOLD)}")
    print(c("  +---------------------------------------------+", CYAN))
    print()
    if interactive:
        input("  Press Enter to return to menu...")
    else:
        print(c("  [AUTO] Vault encrypted by watchdog.", GREEN))
    return True

# ── DECRYPT ─────────────────────────────────────

def decrypt_vault():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           DECRYPT MODE", BOLD + YELLOW))
    print(f"{BOLD}+{'='*48}+{RESET}\n")

    brain_folder = get_brain_folder()

    if not os.path.exists(brain_folder):
        print(c(f"  Brain folder not found: {brain_folder}", RED))
        print(c("  Go to Config > Set Brain folder to fix this.\n", YELLOW))
        input("  Press Enter to return to menu...")
        return

    manifest_path = os.path.join(brain_folder, MANIFEST_FILE)
    if not os.path.exists(manifest_path):
        print(c("  No manifest found. Nothing to decrypt.\n", RED))
        input("  Press Enter to return to menu...")
        return

    mode = get_manifest_mode(manifest_path)
    if mode is None:
        print(c("  Manifest uses an unknown or corrupted format.", RED))
        input("  Press Enter to return to menu...")
        return
    mode_text = 'ML-KEM-768 ' + PQC_BADGE if mode == 'ml-kem-768' else 'RSA-4096 (legacy)'
    print(f"  {c('Manifest encryption:', CYAN)} {mode_text}\n")

    if mode == 'ml-kem-768':
        priv_key_file, _ = get_mlkem_key_paths()
        if not os.path.exists(priv_key_file):
            print(c("  ML-KEM-768 private key not found!", RED))
            print(f"  Expected: {priv_key_file}\n")
            input("  Press Enter to return to menu...")
            return
        password = getpass.getpass("  Enter ML-KEM-768 private key password\n  (press Enter if none): ") or ""
        try:
            private_key = read_mlkem_private_key(priv_key_file, password)
        except Exception:
            print(c("\n  Wrong password or corrupted key file", RED))
            input("  Press Enter to return to menu...")
            return
        decrypt_blob = mlkem_hybrid_decrypt
        file_header = MLKEM_MAGIC
    else:
        priv_key_file, pub_key_file = get_key_paths()
        if not os.path.exists(priv_key_file):
            print(c("  Private key not found!", RED))
            print(f"  Expected: {priv_key_file}\n" + c("  Go to Config > Set Keys folder.\n", YELLOW))
            input("  Press Enter to return to menu...")
            return
        password = getpass.getpass("  Enter private key password\n  (press Enter if none): ") or ""
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=password.encode() if password else None, backend=default_backend()
                )
        except Exception:
            print(c("\n  Wrong password or corrupted key file", RED))
            input("  Press Enter to return to menu...")
            return
        decrypt_blob = hybrid_decrypt
        file_header = MAGIC_HEADER
    print(c("  Private key loaded\n", GREEN))

    with open(manifest_path, 'rb') as f:
        f.read(len(file_header))
        raw = base64.b64decode(f.read())
    manifest = json.loads(decrypt_blob(raw, private_key))

    if isinstance(manifest, dict) and isinstance(manifest.get('files'), dict):
        file_map = manifest['files']
    else:
        file_map = manifest

    if not file_map:
        print(c("  Manifest is empty.\n", YELLOW))
        input("  Press Enter to return to menu...")
        return

    print(c(f"  Manifest contains {len(file_map)} file(s)\n", YELLOW))
    print(c("  +---------------------------------------------+", CYAN))
    print(c("    DECRYPTING", BOLD))
    print(c("  +---------------------------------------------+", CYAN))

    decrypted_count = 0
    items = list(file_map.items())
    pending = []

    for i, (safe_name, orig_rel) in enumerate(items, 1):
        enc_full = os.path.normpath(os.path.join(brain_folder, safe_name))
        orig_full = os.path.normpath(os.path.join(brain_folder, orig_rel))

        if not os.path.exists(enc_full):
            progress_bar(i, len(items))
            continue

        try:
            with open(enc_full, 'rb') as f:
                fhead = f.read(32)
                f.seek(0)
                f.read(len(file_header))
                raw_content = base64.b64decode(f.read())
            if not fhead.startswith(file_header):
                print(c(f"\n  Skipping {safe_name}: encrypted with a different method", YELLOW))
                progress_bar(i, len(items))
                continue
            dec_content = decrypt_blob(raw_content, private_key)

            os.remove(enc_full)
            pending.append((orig_full, dec_content))
            decrypted_count += 1
        except Exception as e:
            print(c(f"\n  Error decrypting {safe_name}: {e}", RED))

        progress_bar(i, len(items))

    for orig_full, dec_content in pending:
        os.makedirs(os.path.dirname(orig_full), exist_ok=True)
        with open(orig_full, 'wb') as f:
            f.write(dec_content)

    os.remove(manifest_path)

    print()
    print(c("  +---------------------------------------------+", CYAN))
    print(f"  {c('[OK]', GREEN)} {c('Decrypted:', BOLD)} {decrypted_count}")
    print(c("  +---------------------------------------------+", CYAN))
    print()
    input("  Press Enter to return to menu...")

# ── MAIN ────────────────────────────────────────

def main():
    global script_dir
    if getattr(sys, 'frozen', False):
        script_dir = os.path.dirname(sys.executable)
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))

    threading.Thread(target=watchdog_loop, daemon=True, name='watchdog').start()

    while True:
        show_menu()
        choice = input(f"  {c('Enter choice', YELLOW)} ({c('1-4', CYAN)}): ").strip()
        if choice == '1':
            encrypt_vault()
        elif choice == '2':
            decrypt_vault()
        elif choice == '3':
            show_config()
        elif choice == '4':
            clear()
            print(f"\n  Goodbye!\n\n")
            sys.exit(0)
        else:
            print(c("\n  Invalid choice.", RED))
            input("  Press Enter to continue...")

if __name__ == '__main__':
    main()
