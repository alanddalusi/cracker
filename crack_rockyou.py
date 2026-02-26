#!/usr/bin/env python3
"""
Cracker de hashes bcrypt usando rockyou.txt con multiprocessing.
"""
import bcrypt
import time
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# Hashes extraídos del archivo shadow
USERS = {
    "root":    b"$2a$10$og/Yjq7B5iYkj0vxMqtiAukrC0fFc7Q9oXKGZAjr.PUVJ3dUMP.3u",
    "eduardo": b"$2a$10$JZjkKeD5600KQiUG0fHq3udcLKcoY19597vYjSVq/AMQ2i4.S7W/6",
    "laura":   b"$2a$10$5mf8SVHUg1tSw6c.fpgkSOv4y/rjoC.oO5iYKCafSX1fbeW1PYctG",
    "jose":    b"$2a$10$roLcBYMh78zySl18hAStdeIH9dYvxkn0LqNoBsJ5iUldWmZ6JB036",
}

MAX_WORDS = 10000  # Top 10,000 passwords from rockyou


def try_passwords_for_user(args):
    """Worker function: try a batch of passwords against one user's hash."""
    username, hash_bytes, passwords = args
    for i, pwd in enumerate(passwords):
        try:
            pwd_bytes = pwd.encode('utf-8', errors='ignore')
            if bcrypt.checkpw(pwd_bytes, hash_bytes):
                return (username, pwd, i)
        except Exception:
            continue
    return (username, None, len(passwords))


def load_wordlist(path, max_words):
    """Load wordlist from file."""
    words = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if word:
                words.append(word)
            if len(words) >= max_words:
                break
    return words


def main():
    wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockyou.txt")
    
    print("=" * 60)
    print("  CRACKER BCRYPT con rockyou.txt + multiprocessing")
    print("=" * 60)
    
    print(f"\n[*] Cargando las top {MAX_WORDS} contraseñas de rockyou.txt...")
    passwords = load_wordlist(wordlist_path, MAX_WORDS)
    print(f"[*] Cargadas: {len(passwords)} palabras")
    
    num_cpus = multiprocessing.cpu_count()
    print(f"[*] CPUs disponibles: {num_cpus}")
    print(f"[*] Tipo de hash: bcrypt ($2a$) cost factor 10")
    est_time = len(passwords) * 0.1 / 60
    print(f"[*] Tiempo estimado por usuario: ~{est_time:.1f} min")
    print(f"[*] Usando {num_cpus} procesos en paralelo para los {len(USERS)} usuarios")
    print(f"[*] Tiempo estimado total: ~{est_time * len(USERS) / num_cpus:.1f} min")
    print("-" * 60)

    total_start = time.time()
    results = {}
  
    # Prepare tasks - one per user
    tasks = []
    for username, hash_bytes in USERS.items():
        tasks.append((username, hash_bytes, passwords))

    # Run all users in parallel using multiprocessing
    with ProcessPoolExecutor(max_workers=min(num_cpus, len(USERS))) as executor:
        futures = {executor.submit(try_passwords_for_user, task): task[0] for task in tasks}
        
        for future in as_completed(futures):
            username = futures[future]
            try:
                uname, password, attempts = future.result()
                if password:
                    elapsed = time.time() - total_start
                    print(f"  [+] {uname:12s} -> {password} (intento #{attempts+1}, {elapsed:.1f}s)")
                    results[uname] = password
                else:
                    elapsed = time.time() - total_start
                    print(f"  [-] {uname:12s} -> NO encontrada ({attempts} intentos, {elapsed:.1f}s)")
                    results[uname] = None
            except Exception as e:
                print(f"  [!] {username}: Error - {e}")
                results[username] = None
    
    total_elapsed = time.time() - total_start
    
    print("\n" + "=" * 60)
    print("  RESULTADOS FINALES")
    print("=" * 60)
    
    cracked = 0
    for username in USERS:
        pwd = results.get(username)
        if pwd:
            print(f"  {username:12s} -> {pwd}")
            cracked += 1
        else:
            print(f"  {username:12s} -> [NO ENCONTRADA]")
    
    print(f"\n  Crackeadas: {cracked}/{len(USERS)}")
    print(f"  Tiempo total: {total_elapsed:.1f}s")
    
    if cracked < len(USERS):
        print(f"\n  [i] Para las no encontradas, prueba aumentando MAX_WORDS")
        print(f"      o usando John the Ripper / Hashcat para mejor rendimiento")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
