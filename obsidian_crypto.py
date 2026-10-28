import os
import sys
import json

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
    print(f"{BOLD}+{'-'*48}+{RESET}\n")

def show_config():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           CONFIGURATION", BOLD + MAGENTA))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    config = load_config()

    print(c("  Current Settings:\n", YELLOW))
    print(f"  {c('Brain folder:', CYAN)}     {config.get('brain_folder') or '(not set)'}")
    print(f"\n{BOLD}+{'-'*48}+{RESET}\n")
    print(c("  What would you like to configure?\n", YELLOW))
    print(f"  {c('[1]', CYAN)} Set Brain folder path")
    print(f"  {c('[2]', CYAN)} Set Keys folder path")
    print(f"  {c('[3]', CYAN)} Reset to defaults")
    print(f"  {c('[4]', CYAN)} Back to main menu\n")
    choice = input(f"  {c('Enter choice', YELLOW)} ({c('1-4', CYAN)}): ").strip()
    if choice == '1':
        set_brain_folder(config)
    elif choice == '2':
        set_keys_folder(config)
    elif choice == '3':
        reset_config()
    elif choice == '4':
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
    print(c("\n  Keys folder set!", GREEN))
    input("\n  Press Enter to return to config...")

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
    print(c("  Encryption engine not implemented yet.\n", YELLOW))
    input("  Press Enter to return to menu...")

# ── DECRYPT ─────────────────────────────────────

def decrypt_vault():
    clear()
    print(f"\n{BOLD}+{'='*48}+{RESET}")
    print(c("           DECRYPT MODE", BOLD + YELLOW))
    print(f"{BOLD}+{'='*48}+{RESET}\n")
    print(c("  Decryption engine not implemented yet.\n", YELLOW))
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
