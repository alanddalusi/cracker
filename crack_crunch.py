#!/usr/bin/env python3
"""
Cracker bcrypt usando wordlist generada por crunch o pistas del profesor.
Tarea de clase - uso educativo.

USO:
  1) Con crunch (genera diccionario por pipe):
     crunch 6 8 -t @@pass | python crack_crunch.py --stdin

  2) Con archivo de crunch:
     crunch 5 7 abc123 -o custom.txt
     python crack_crunch.py --wordlist custom.txt

  3) Con patrón directo (sin crunch instalado):
     python crack_crunch.py --pattern "??pass"      # 2 chars desconocidos + "pass"
     python crack_crunch.py --pattern "a?b?"         # chars fijos + desconocidos
     python crack_crunch.py --pattern "????"         # fuerza bruta 4 chars
     python crack_crunch.py --known-chars "a__b__"   # _ = desconocido

  Símbolos para --pattern:
     ?  = cualquier letra minúscula (a-z)
     #  = cualquier dígito (0-9)
     *  = letra o dígito (a-z, 0-9)
     Cualquier otro carácter = literal

EJEMPLOS con pistas del profesor:
  - "La contraseña de eduardo empieza por 'ma' y tiene 6 letras":
    python crack_crunch.py --pattern "ma????" --user eduardo

  - "La contraseña de laura tiene 5 caracteres, empieza por 's' y termina en '3'":
    python crack_crunch.py --pattern "s??#3" --user laura --charset lower+digits
"""
import bcrypt
import time
import sys
import itertools
import string
from concurrent.futures import ProcessPoolExecutor
import argparse

# Hashes pendientes de crackear
USERS = {
    "eduardo": b"$2a$10$JZjkKeD5600KQiUG0fHq3udcLKcoY19597vYjSVq/AMQ2i4.S7W/6",
    "laura":   b"$2a$10$5mf8SVHUg1tSw6c.fpgkSOv4y/rjoC.oO5iYKCafSX1fbeW1PYctG",
}

# Contraseñas ya crackeadas
CRACKED = {
    "root": "cleopatra",
    "jose": "robocop",
}

CHARSETS = {
    "lower":        string.ascii_lowercase,
    "upper":        string.ascii_uppercase,
    "digits":       string.digits,
    "lower+digits": string.ascii_lowercase + string.digits,
    "alpha":        string.ascii_lowercase + string.ascii_uppercase,
    "all":          string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%&*",
}


def generate_from_pattern(pattern, charset="lower"):
    """
    Genera candidatos a partir de un patrón:
      ? = cualquier letra minúscula
      # = cualquier dígito
      * = letra minúscula o dígito
      otro carácter = literal
    """
    char_sets = []
    for ch in pattern:
        if ch == '?':
            char_sets.append(string.ascii_lowercase)
        elif ch == '#':
            char_sets.append(string.digits)
        elif ch == '*':
            char_sets.append(string.ascii_lowercase + string.digits)
        elif ch == '@':
            char_sets.append(CHARSETS.get(charset, string.ascii_lowercase))
        else:
            char_sets.append(ch)

    count = 1
    for cs in char_sets:
        count *= len(cs)

    print(f"[*] Patrón: '{pattern}' -> {count:,} combinaciones posibles")

    for combo in itertools.product(*char_sets):
        yield ''.join(combo)


def try_batch(args):
    """Worker: prueba un lote de contraseñas contra un hash."""
    username, hash_bytes, passwords = args
    for i, pwd in enumerate(passwords):
        try:
            pwd_bytes = pwd.encode('utf-8', errors='ignore')
            if bcrypt.checkpw(pwd_bytes, hash_bytes):
                return (username, pwd, True)
        except Exception:
            continue
    return (username, None, False)


def crack_user(username, hash_bytes, password_generator, batch_size=50):
    """Intenta crackear un usuario con generador de contraseñas."""
    print(f"\n[*] Atacando: {username}")
    start = time.time()
    attempts = 0

    batch = []
    for pwd in password_generator:
        batch.append(pwd)
        attempts += 1

        if len(batch) >= batch_size:
            for p in batch:
                try:
                    if bcrypt.checkpw(p.encode('utf-8', errors='ignore'), hash_bytes):
                        elapsed = time.time() - start
                        print(f"  [+] ¡ENCONTRADA! {username} -> {p}")
                        print(f"      Intentos: {attempts:,} | Tiempo: {elapsed:.1f}s")
                        return p
                except Exception:
                    continue

            elapsed = time.time() - start
            speed = attempts / elapsed if elapsed > 0 else 0
            print(f"\r  [.] {attempts:,} intentos | {elapsed:.1f}s | {speed:.1f} pwd/s", end="", flush=True)
            batch = []

    # Últimos que queden en el batch
    for p in batch:
        try:
            if bcrypt.checkpw(p.encode('utf-8', errors='ignore'), hash_bytes):
                elapsed = time.time() - start
                print(f"\n  [+] ¡ENCONTRADA! {username} -> {p}")
                print(f"      Intentos: {attempts:,} | Tiempo: {elapsed:.1f}s")
                return p
        except Exception:
            continue

    elapsed = time.time() - start
    print(f"\n  [-] No encontrada. {attempts:,} intentos en {elapsed:.1f}s")
    return None


def read_stdin():
    """Lee contraseñas de stdin (pipe desde crunch)."""
    for line in sys.stdin:
        word = line.strip()
        if word:
            yield word


def read_wordlist(path):
    """Lee contraseñas de un archivo."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if word:
                yield word


def main():
    parser = argparse.ArgumentParser(
        description="Cracker bcrypt con crunch/patrones - Tarea de clase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS:
  python crack_crunch.py --pattern "ma????" --user eduardo
  python crack_crunch.py --pattern "s**#3" --user laura
  crunch 6 6 -t @@@@ss | python crack_crunch.py --stdin --user eduardo
  python crack_crunch.py --wordlist custom.txt
        """
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--pattern', help='Patrón: ? = letra, # = dígito, * = alfanum')
    source.add_argument('--stdin', action='store_true', help='Leer passwords de stdin (pipe de crunch)')
    source.add_argument('--wordlist', help='Ruta a archivo de diccionario')

    parser.add_argument('--user', choices=list(USERS.keys()), help='Atacar solo este usuario')
    parser.add_argument('--charset', choices=list(CHARSETS.keys()), default='lower',
                        help='Charset para @ en patrones (default: lower)')

    args = parser.parse_args()

    print("=" * 60)
    print("  CRACKER BCRYPT con crunch/patrones")
    print("=" * 60)

    print(f"\n[i] Contraseñas ya crackeadas:")
    for user, pwd in CRACKED.items():
        print(f"    {user:12s} -> {pwd}")

    # Seleccionar usuarios a atacar
    if args.user:
        targets = {args.user: USERS[args.user]}
    else:
        targets = USERS

    print(f"\n[*] Usuarios pendientes: {', '.join(targets.keys())}")

    results = {}

    for username, hash_bytes in targets.items():
        if args.pattern:
            gen = generate_from_pattern(args.pattern, args.charset)
        elif args.stdin:
            gen = read_stdin()
        elif args.wordlist:
            gen = read_wordlist(args.wordlist)

        result = crack_user(username, hash_bytes, gen)
        results[username] = result

    # Resumen final
    print("\n" + "=" * 60)
    print("  RESUMEN COMPLETO")
    print("=" * 60)
    
    all_results = {**CRACKED}
    for user, pwd in results.items():
        if pwd:
            all_results[user] = pwd
    
    all_users = ["root", "eduardo", "laura", "jose"]
    for user in all_users:
        pwd = all_results.get(user)
        if pwd:
            print(f"  {user:12s} -> {pwd}")
        else:
            print(f"  {user:12s} -> [PENDIENTE]")

    print(f"\n  Crackeadas: {len(all_results)}/4")
    print("=" * 60)


if __name__ == "__main__":
    main()
