import os
import sys
import base64
import json
import getpass
import secrets
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC_HEADER = b'VAULTRSA_v1\n'
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

DEFAULT_CONFIG = {
    'brain_folder': '',
    'private_key': '',
    'public_key': '',
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
        return head.startswith(MAGIC_HEADER)
    except:
        return False

def get_manifest_mode(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(32)
    except Exception:
        return None
    if head.startswith(MAGIC_HEADER):
        return 'rsa-4096'
    return None

# ── HYBRID ENCRYPTION (AES-256-GCM + RSA-4096) ──

AES_KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

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

# ── UI ──────────────────────────────────────────

def show_menu():
    clear()
    config = load_config()
    bf = config.get('brain_folder', '') or '(not set)'
    kf = config.get('private_key', '') or '(not set)'

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
    print(f"   {c('Encryption:', CYAN)}    RSA-4096 + AES-256-GCM")
    print(f"{BOLD}+{'-'*48}+{RESET}\n")

def show_config():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           CONFIGURATION", BOLD + MAGENTA))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    config = load_config()

    print(c("  Current Settings:\n", YELLOW))
    print(f"  {c('Brain folder:', CYAN)}     {config.get('brain_folder') or '(not set)'}")
    print(f"  {c('Encryption:', CYAN)}       RSA-4096 + AES-256-GCM")
    print(f"\n{BOLD}+{'-'*48}+{RESET}\n")
    print(c("  What would you like to configure?\n", YELLOW))
    print(f"  {c('[1]', CYAN)} Set Brain folder path")
    print(f"  {c('[2]', CYAN)} Set Keys folder path")
    print(f"  {c('[3]', CYAN)} Generate new RSA-4096 keys")
    print(f"  {c('[4]', CYAN)} Reset to defaults")
    print(f"  {c('[5]', CYAN)} Back to main menu\n")
    choice = input(f"  {c('Enter choice', YELLOW)} ({c('1-5', CYAN)}): ").strip()
    if choice == '1':
        set_brain_folder(config)
    elif choice == '2':
        set_keys_folder(config)
    elif choice == '3':
        generate_rsa_keys()
    elif choice == '4':
        reset_config()
    elif choice == '5':
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
    else:
        config['private_key'] = os.path.join(script_dir, 'private_key.pem')
        config['public_key'] = os.path.join(script_dir, 'public_key.pem')
    save_config(config)
    if os.path.exists(config['public_key']):
        print(c("\n  RSA-4096 keys found in this folder!", GREEN))
    else:
        print(c("\n  No RSA-4096 keys found in this folder yet.", YELLOW))
        gen = input("  Generate new RSA-4096 keys now? (Y/n): ").strip().lower()
        if gen != 'n':
            generate_rsa_keys()
            return
    input("\n  Press Enter to return to config...")

def generate_rsa_keys():
    config = load_config()
    priv, pub = get_key_paths()
    if os.path.exists(priv):
        clear()
        print(f"\n{BOLD}+{'='*48}+{RESET}")
        print(c("         RSA-4096 KEY GENERATION", BOLD + MAGENTA))
        print(f"{BOLD}+{'='*48}+{RESET}\n")
        print(c("  RSA-4096 keys already exist!\n", YELLOW))
        print(f"  Private: {priv}")
        print(f"  Public:  {pub}\n")
        if input("  Overwrite? (y/N): ").strip().lower() != 'y':
            print(c("\n  Cancelled.\n", YELLOW))
            input("  Press Enter to return...")
            return
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("         RSA-4096 KEY GENERATION", BOLD + MAGENTA))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    print(c("  Generating RSA-4096 keypair...\n", YELLOW))
    key = serialization.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    password = getpass.getpass("  Enter password to protect private key\n  (press Enter for none): ")
    os.makedirs(os.path.dirname(priv), exist_ok=True)
    enc = serialization.BestAvailableEncryption(password.encode('utf-8')) if password else serialization.NoEncryption()
    with open(priv, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        ))
    with open(pub, 'wb') as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(c("\n  Keys generated successfully!", GREEN))
    print(f"\n  {c(os.path.basename(priv), BOLD)}  <- {c('KEEP THIS SECRET!', RED)}")
    print(f"  {c(os.path.basename(pub), BOLD)}   <- {c('Safe to share', CYAN)}")
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

# ── ENCRYPT ─────────────────────────────────────

def encrypt_vault():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           ENCRYPT MODE", BOLD + GREEN))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    run_encrypt(interactive=True)

def run_encrypt(interactive=True):
    print(f"  {c('Encryption method:', CYAN)} RSA-4096 + AES-256-GCM\n")

    brain_folder = get_brain_folder()

    if not os.path.exists(brain_folder):
        print(c(f"  Brain folder not found: {brain_folder}", RED))
        print(c("  Go to Config > Set Brain folder to fix this.\n", YELLOW))
        if interactive:
            input("  Press Enter to return to menu...")
        return False

    manifest_path = os.path.join(brain_folder, MANIFEST_FILE)

    print(c("  Loading RSA-4096 public key...", YELLOW))
    _, pub_key_file = get_key_paths()
    if not os.path.exists(pub_key_file):
        print(c("  Public key not found!", RED))
        print(f"  Expected: {pub_key_file}\n" + c("  Go to Config > Generate new RSA-4096 keys.\n", YELLOW))
        if interactive:
            input("  Press Enter to return to menu...")
        return False
    with open(pub_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
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
            with open(full, 'rb') as f:
                content = f.read()
            enc_data = hybrid_encrypt(content, public_key)

            with open(full, 'wb') as f:
                f.write(MAGIC_HEADER + base64.b64encode(enc_data))

            manifest_files[rel] = rel
            encrypted_count += 1
        except Exception as e:
            print(c(f"\n  Error encrypting {rel}: {e}", RED))
        progress_bar(i, len(rel_paths))

    manifest = {'files': manifest_files}
    manifest_bytes = json.dumps(manifest, indent=2).encode('utf-8')
    enc_manifest = hybrid_encrypt(manifest_bytes, public_key)
    with open(manifest_path, 'wb') as f:
        f.write(MAGIC_HEADER + base64.b64encode(enc_manifest))

    print()
    print(c("  +---------------------------------------------+", CYAN))
    print(f"  {c('[OK]', GREEN)} {c('Encrypted:', BOLD)} {encrypted_count}")
    print(c("  +---------------------------------------------+", CYAN))
    print()
    if interactive:
        input("  Press Enter to return to menu...")
    else:
        print(c("  Vault encrypted.", GREEN))
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
    print(f"  {c('Manifest encryption:', CYAN)} RSA-4096\n")

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
