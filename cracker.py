#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  HASH CRACKER MULTI-HERRAMIENTA  -  Tarea de clase          ║
║  Soporta: john, hashcat, crunch, hydra + modo Python         ║
║  Auto-detecta tipo de hash y elige la mejor estrategia       ║
╚══════════════════════════════════════════════════════════════╝

USO RÁPIDO (modo automático - RECOMENDADO PARA EXAMEN):
  python3 cracker.py auto -H '$2a$10$og/Yjq7...'
  python3 cracker.py auto -f shadow.txt
  python3 cracker.py auto -f shadow.txt -w rockyou.txt

CON PISTAS DEL PROFESOR:
  python3 cracker.py pistas -H '$2a$10$...' --empieza "ma" --longitud 6
  python3 cracker.py pistas -H '$2a$10$...' --termina "23" --longitud 5
  python3 cracker.py pistas -H '$2a$10$...' --contiene "pass" --longitud 8
  python3 cracker.py pistas -H '$2a$10$...' --patron "ma????" 
  python3 cracker.py pistas -f hashes.txt --empieza "ab" --longitud 5 --charset lower

HERRAMIENTA ESPECÍFICA:
  python3 cracker.py john -f shadow.txt -w rockyou.txt
  python3 cracker.py hashcat -H '$6$salt$hash...' -w rockyou.txt
  python3 cracker.py crunch -H '$2a$10$...' --patron "ma????"
  python3 cracker.py hydra -s ssh://192.168.1.10 -u admin -w rockyou.txt

Uso educativo - Seguridad Informática.
"""

import subprocess
import sys
import os
import re
import shutil
import time
import argparse
import tempfile
import signal
import itertools
import string

# ─────────────────────────────────────────────────────────────
#  IDENTIFICACIÓN DE HASHES
# ─────────────────────────────────────────────────────────────

HASH_TYPES = {
    # (regex, nombre, john_format, hashcat_mode, es_lento)
    "bcrypt": {
        "regex": r"^\$2[aby]?\$\d{2}\$.{53}$",
        "name": "bcrypt",
        "john_format": "bcrypt",
        "hashcat_mode": "3200",
        "slow": True,
        "description": "bcrypt - MUY LENTO (~20-50 pwd/s con john)",
    },
    "sha512crypt": {
        "regex": r"^\$6\$[^\$]+\$[a-zA-Z0-9./]{86}$",
        "name": "sha512crypt",
        "john_format": "sha512crypt",
        "hashcat_mode": "1800",
        "slow": True,
        "description": "SHA-512 crypt (Linux) - LENTO",
    },
    "sha256crypt": {
        "regex": r"^\$5\$[^\$]+\$[a-zA-Z0-9./]{43}$",
        "name": "sha256crypt",
        "john_format": "sha256crypt",
        "hashcat_mode": "7400",
        "slow": True,
        "description": "SHA-256 crypt (Linux) - LENTO",
    },
    "md5crypt": {
        "regex": r"^\$1\$[^\$]+\$[a-zA-Z0-9./]{22}$",
        "name": "md5crypt",
        "john_format": "md5crypt",
        "hashcat_mode": "500",
        "slow": False,
        "description": "MD5 crypt (Linux antiguo)",
    },
    "descrypt": {
        "regex": r"^[a-zA-Z0-9./]{13}$",
        "name": "descrypt",
        "john_format": "descrypt",
        "hashcat_mode": "1500",
        "slow": False,
        "description": "DES crypt (muy antiguo)",
    },
    "md5": {
        "regex": r"^[a-fA-F0-9]{32}$",
        "name": "MD5 (raw)",
        "john_format": "Raw-MD5",
        "hashcat_mode": "0",
        "slow": False,
        "description": "MD5 sin salt - MUY RÁPIDO",
    },
    "sha1": {
        "regex": r"^[a-fA-F0-9]{40}$",
        "name": "SHA-1 (raw)",
        "john_format": "Raw-SHA1",
        "hashcat_mode": "100",
        "slow": False,
        "description": "SHA-1 sin salt - RÁPIDO",
    },
    "sha256": {
        "regex": r"^[a-fA-F0-9]{64}$",
        "name": "SHA-256 (raw)",
        "john_format": "Raw-SHA256",
        "hashcat_mode": "1400",
        "slow": False,
        "description": "SHA-256 sin salt - RÁPIDO",
    },
    "sha512": {
        "regex": r"^[a-fA-F0-9]{128}$",
        "name": "SHA-512 (raw)",
        "john_format": "Raw-SHA512",
        "hashcat_mode": "1700",
        "slow": False,
        "description": "SHA-512 sin salt - RÁPIDO",
    },
    "ntlm": {
        "regex": r"^[a-fA-F0-9]{32}$",  # mismo que MD5, se diferencia por contexto
        "name": "NTLM",
        "john_format": "NT",
        "hashcat_mode": "1000",
        "slow": False,
        "description": "NTLM (Windows) - MUY RÁPIDO",
    },
    "mysql": {
        "regex": r"^\*[A-F0-9]{40}$",
        "name": "MySQL",
        "john_format": "mysql-sha1",
        "hashcat_mode": "300",
        "slow": False,
        "description": "MySQL >=4.1 - RÁPIDO",
    },
    "apr1": {
        "regex": r"^\$apr1\$[^\$]+\$[a-zA-Z0-9./]{22}$",
        "name": "Apache APR1",
        "john_format": "md5crypt",
        "hashcat_mode": "1600",
        "slow": False,
        "description": "Apache APR1 MD5",
    },
    "yescrypt": {
        "regex": r"^\$y\$[^\$]+\$[^\$]+\$[a-zA-Z0-9./]+$",
        "name": "yescrypt",
        "john_format": "crypt",
        "hashcat_mode": None,
        "slow": True,
        "description": "yescrypt (Linux moderno) - MUY LENTO",
    },
}


def identify_hash(hash_str):
    """Identifica el tipo de hash automáticamente."""
    # Limpiar el hash
    hash_str = hash_str.strip()
    
    # Si viene en formato shadow (user:hash:...)
    if ':' in hash_str:
        parts = hash_str.split(':')
        if len(parts) >= 2:
            hash_str = parts[1]
    
    results = []
    for key, info in HASH_TYPES.items():
        if re.match(info["regex"], hash_str):
            results.append((key, info))
    
    # Si detectamos MD5 raw (32 hex chars), puede ser MD5 o NTLM
    # Priorizamos MD5 por ser más común en ejercicios
    if len(results) > 1:
        # Filtrar duplicados, priorizar
        priority = ["bcrypt", "sha512crypt", "sha256crypt", "md5crypt", 
                     "yescrypt", "apr1", "mysql", "md5", "sha1", "sha256", "sha512"]
        results.sort(key=lambda x: priority.index(x[0]) if x[0] in priority else 99)
    
    return results


def print_hash_info(hash_str):
    """Muestra información detallada del hash detectado."""
    results = identify_hash(hash_str)
    
    if not results:
        print(f"  [!] No se pudo identificar el hash: {hash_str[:50]}...")
        print(f"      Longitud: {len(hash_str)} caracteres")
        return None
    
    primary = results[0]
    print(f"  [+] Tipo detectado: {primary[1]['name']}")
    print(f"      {primary[1]['description']}")
    print(f"      John format:   --format={primary[1]['john_format']}")
    if primary[1]['hashcat_mode']:
        print(f"      Hashcat mode:  -m {primary[1]['hashcat_mode']}")
    if primary[1]['slow']:
        print(f"      ⚠  Hash LENTO - usar diccionario pequeño o pistas")
    
    if len(results) > 1:
        print(f"      También podría ser: {', '.join(r[1]['name'] for r in results[1:])}")
    
    return primary


# ─────────────────────────────────────────────────────────────
#  DETECCIÓN DE HERRAMIENTAS DISPONIBLES
# ─────────────────────────────────────────────────────────────

def find_tool(name):
    """Busca una herramienta en el sistema."""
    return shutil.which(name)


def check_tools():
    """Detecta qué herramientas están disponibles."""
    tools = {}
    for tool in ["john", "hashcat", "crunch", "hydra"]:
        path = find_tool(tool)
        tools[tool] = path
        if path:
            print(f"  [✓] {tool:10s} -> {path}")
        else:
            print(f"  [✗] {tool:10s} -> no encontrado")
    
    # Verificar si bcrypt está disponible para modo Python
    try:
        import bcrypt
        tools["python-bcrypt"] = True
        print(f"  [✓] {'python+bcrypt':10s} -> disponible (fallback)")
    except ImportError:
        tools["python-bcrypt"] = False
        print(f"  [✗] {'python+bcrypt':10s} -> pip install bcrypt")
    
    return tools


def find_wordlist():
    """Busca wordlists comunes en el sistema."""
    common_paths = [
        # En el directorio actual
        "rockyou.txt",
        # Kali Linux / Parrot
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        # SecLists
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
        # John
        "/usr/share/john/password.lst",
        "/etc/john/password.lst",
        # Otros
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    
    found = []
    for path in common_paths:
        if os.path.isfile(path):
            size = os.path.getsize(path) / (1024 * 1024)  # MB
            found.append((path, size))
    
    return found


# ─────────────────────────────────────────────────────────────
#  PREPARACIÓN DE ARCHIVOS
# ─────────────────────────────────────────────────────────────

def parse_shadow_file(filepath):
    """Parsea un archivo shadow y extrae usuario:hash."""
    entries = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) >= 2 and parts[1] and parts[1] not in ('*', '!', '!!', 'x'):
                entries.append({
                    "user": parts[0],
                    "hash": parts[1],
                    "full_line": line,
                })
    return entries


def create_hash_file(entries, output_path=None):
    """Crea archivo temporal con hashes para john/hashcat."""
    if output_path is None:
        fd, output_path = tempfile.mkstemp(suffix='.txt', prefix='hashes_')
        os.close(fd)
    
    with open(output_path, 'w') as f:
        for entry in entries:
            f.write(f"{entry['user']}:{entry['hash']}\n")
    
    return output_path


# ─────────────────────────────────────────────────────────────
#  COMANDOS DE CRACKING
# ─────────────────────────────────────────────────────────────

def run_john(hash_file, wordlist=None, format_type=None, extra_args=None):
    """Ejecuta John the Ripper."""
    cmd = ["john"]
    
    if format_type:
        cmd.append(f"--format={format_type}")
    
    if wordlist:
        cmd.append(f"--wordlist={wordlist}")
    
    if extra_args:
        cmd.extend(extra_args)
    
    cmd.append(hash_file)
    
    print(f"\n  [>] Ejecutando: {' '.join(cmd)}")
    print(f"  [i] Pulsa Ctrl+C para parar\n")
    
    try:
        proc = subprocess.run(cmd, timeout=None)
    except KeyboardInterrupt:
        print("\n  [!] Interrumpido por el usuario")
    
    # Mostrar resultados
    print(f"\n  [*] Mostrando contraseñas encontradas:")
    show_cmd = ["john", "--show"]
    if format_type:
        show_cmd.append(f"--format={format_type}")
    show_cmd.append(hash_file)
    subprocess.run(show_cmd)


def run_hashcat(hash_file, mode, wordlist=None, mask=None, extra_args=None):
    """Ejecuta Hashcat."""
    cmd = ["hashcat", "-m", str(mode)]
    
    if mask:
        # Modo máscara (modo 3)
        cmd.extend(["-a", "3"])
        cmd.append(hash_file)
        cmd.append(mask)
    elif wordlist:
        # Modo diccionario (modo 0)
        cmd.extend(["-a", "0"])
        cmd.append(hash_file)
        cmd.append(wordlist)
    else:
        cmd.append(hash_file)
    
    if extra_args:
        cmd.extend(extra_args)
    
    # Optimizaciones: forzar CPU si no hay GPU
    cmd.extend(["--force", "-O"])
    
    print(f"\n  [>] Ejecutando: {' '.join(cmd)}")
    print(f"  [i] Pulsa Ctrl+C para parar\n")
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n  [!] Interrumpido por el usuario")
    
    # Mostrar resultados
    print(f"\n  [*] Mostrando contraseñas encontradas:")
    subprocess.run(["hashcat", "-m", str(mode), hash_file, "--show"])


def run_crunch_to_john(min_len, max_len, charset, template, john_hash_file, john_format):
    """Genera contraseñas con crunch y las pasa a john por pipe."""
    crunch_cmd = ["crunch", str(min_len), str(max_len)]
    
    if charset:
        crunch_cmd.append(charset)
    if template:
        crunch_cmd.extend(["-t", template])
    
    john_cmd = ["john", f"--format={john_format}", "--stdin", john_hash_file]
    
    full_cmd = f"{' '.join(crunch_cmd)} | {' '.join(john_cmd)}"
    print(f"\n  [>] Ejecutando: {full_cmd}")
    print(f"  [i] Pulsa Ctrl+C para parar\n")
    
    try:
        subprocess.run(full_cmd, shell=True)
    except KeyboardInterrupt:
        print("\n  [!] Interrumpido por el usuario")
    
    # Mostrar resultados
    print(f"\n  [*] Mostrando contraseñas encontradas:")
    subprocess.run(["john", "--show", f"--format={john_format}", john_hash_file])


def run_hydra(target, username=None, userlist=None, wordlist=None, extra_args=None):
    """Ejecuta Hydra para fuerza bruta de servicios."""
    # Parsear target: protocolo://host:puerto
    match = re.match(r"(\w+)://([^:]+)(?::(\d+))?", target)
    if not match:
        print(f"  [!] Formato de target inválido: {target}")
        print(f"      Usa: protocolo://host[:puerto]  (ej: ssh://192.168.1.10)")
        return
    
    protocol = match.group(1)
    host = match.group(2)
    port = match.group(3)
    
    cmd = ["hydra"]
    
    if username:
        cmd.extend(["-l", username])
    elif userlist:
        cmd.extend(["-L", userlist])
    
    if wordlist:
        cmd.extend(["-P", wordlist])
    
    if port:
        cmd.extend(["-s", port])
    
    cmd.extend(["-t", "4"])  # 4 threads para no saturar
    cmd.extend(["-V"])       # Verbose
    
    if extra_args:
        cmd.extend(extra_args)
    
    cmd.extend([host, protocol])
    
    print(f"\n  [>] Ejecutando: {' '.join(cmd)}")
    print(f"  [i] Pulsa Ctrl+C para parar\n")
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n  [!] Interrumpido por el usuario")


# ─────────────────────────────────────────────────────────────
#  MODO PYTHON (fallback sin herramientas externas)
# ─────────────────────────────────────────────────────────────

def python_crack_bcrypt(hash_bytes, passwords):
    """Crackea bcrypt con Python puro (lento pero funciona)."""
    import bcrypt as bc
    for i, pwd in enumerate(passwords):
        try:
            if bc.checkpw(pwd.encode('utf-8', errors='ignore'), hash_bytes):
                return pwd, i
        except Exception:
            continue
    return None, len(passwords)


def python_crack_generic(hash_str, hash_type, passwords):
    """Crackea hashes rápidos con hashlib."""
    import hashlib
    
    algo_map = {
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
    }
    
    algo = algo_map.get(hash_type)
    if not algo:
        return None, 0
    
    target = hash_str.lower()
    
    for i, pwd in enumerate(passwords):
        h = hashlib.new(algo, pwd.encode('utf-8', errors='ignore')).hexdigest()
        if h == target:
            return pwd, i
    return None, len(passwords)


# ─────────────────────────────────────────────────────────────
#  GENERADOR DE PATRONES (reemplazo de crunch en Python)
# ─────────────────────────────────────────────────────────────

CHARSET_MAP = {
    "lower":        string.ascii_lowercase,
    "upper":        string.ascii_uppercase,
    "digits":       string.digits,
    "lower+digits": string.ascii_lowercase + string.digits,
    "upper+digits": string.ascii_uppercase + string.digits,
    "alpha":        string.ascii_letters,
    "alpha+digits": string.ascii_letters + string.digits,
    "all":          string.ascii_letters + string.digits + "!@#$%&*._-",
    "special":      "!@#$%^&*()_+-=[]{}|;:',.<>?/~`",
}


def build_pattern_from_hints(longitud, empieza=None, termina=None, contiene=None, charset="lower"):
    """
    Construye un patrón a partir de las pistas del profesor.
    Devuelve un template para crunch y un patrón interno.
    """
    cs = CHARSET_MAP.get(charset, string.ascii_lowercase)
    
    if longitud is None:
        # Estimar longitud
        total = 0
        if empieza: total += len(empieza)
        if termina: total += len(termina)
        if contiene: total += len(contiene)
        longitud = max(total + 2, 6)  # mínimo 6
        print(f"  [i] Longitud no especificada, estimando: {longitud}")
    
    # Construir patrón
    if empieza and termina:
        middle_len = longitud - len(empieza) - len(termina)
        if middle_len < 0:
            print(f"  [!] Error: empieza({len(empieza)}) + termina({len(termina)}) > longitud({longitud})")
            return None, None, 0
        pattern = empieza + ("?" * middle_len) + termina
    elif empieza:
        remaining = longitud - len(empieza)
        pattern = empieza + ("?" * remaining)
    elif termina:
        remaining = longitud - len(termina)
        pattern = ("?" * remaining) + termina
    elif contiene:
        # Contiene en algún lugar - probar en cada posición
        remaining = longitud - len(contiene)
        if remaining < 0:
            print(f"  [!] Error: contiene({len(contiene)}) > longitud({longitud})")
            return None, None, 0
        # Generaremos múltiples patrones
        patterns = []
        for pos in range(remaining + 1):
            p = ("?" * pos) + contiene + ("?" * (remaining - pos))
            patterns.append(p)
        
        total = sum(count_pattern_size(p, cs) for p in patterns)
        print(f"  [*] 'contiene' genera {len(patterns)} posiciones posibles")
        return patterns, charset, total
    else:
        pattern = "?" * longitud
    
    total = count_pattern_size(pattern, cs)
    return [pattern], charset, total


def count_pattern_size(pattern, charset):
    """Cuenta cuántas combinaciones genera un patrón."""
    count = 1
    for ch in pattern:
        if ch == '?':
            count *= len(charset)
        elif ch == '#':
            count *= 10
        elif ch == '*':
            count *= 36
    return count


def generate_passwords_from_pattern(pattern, charset="lower"):
    """Genera contraseñas a partir de un patrón."""
    cs = CHARSET_MAP.get(charset, charset)
    
    char_sets = []
    for ch in pattern:
        if ch == '?':
            char_sets.append(cs)
        elif ch == '#':
            char_sets.append(string.digits)
        elif ch == '*':
            char_sets.append(string.ascii_lowercase + string.digits)
        else:
            char_sets.append(ch)
    
    for combo in itertools.product(*char_sets):
        yield ''.join(combo)


def hints_to_crunch_template(pattern):
    """Convierte nuestro patrón al formato de crunch."""
    # crunch usa: @ = lower, , = upper, % = digit, ^ = symbol
    template = ""
    for ch in pattern:
        if ch == '?':
            template += '@'   # letra minúscula en crunch
        elif ch == '#':
            template += '%'   # dígito en crunch
        elif ch == '*':
            template += '@'   # simplificamos
        else:
            template += ch    # literal
    return template


# ─────────────────────────────────────────────────────────────
#  ESTRATEGIA AUTOMÁTICA (modo experto)
# ─────────────────────────────────────────────────────────────

def auto_strategy(entries, tools, wordlist_path=None):
    """
    Modo experto: elige automáticamente la mejor herramienta y estrategia.
    Prioridad: hashcat (GPU) > john (CPU) > python (fallback)
    """
    if not entries:
        print("  [!] No hay hashes para crackear")
        return
    
    # Identificar tipo de hash (todos deberían ser iguales)
    sample_hash = entries[0]["hash"]
    detected = identify_hash(sample_hash)
    
    if not detected:
        print(f"  [!] No se pudo identificar el tipo de hash")
        print(f"      Hash: {sample_hash[:60]}...")
        return
    
    hash_key, hash_info = detected[0]
    
    print(f"\n{'─' * 60}")
    print(f"  ESTRATEGIA AUTOMÁTICA")
    print(f"{'─' * 60}")
    print(f"  Hash:     {hash_info['name']}")
    print(f"  Usuarios: {len(entries)}")
    print(f"  Lento:    {'Sí ⚠' if hash_info['slow'] else 'No ✓'}")
    
    # Buscar wordlist
    if not wordlist_path:
        found_wl = find_wordlist()
        if found_wl:
            wordlist_path = found_wl[0][0]
            print(f"  Wordlist: {wordlist_path} ({found_wl[0][1]:.1f} MB)")
        else:
            print(f"  Wordlist: No encontrada")
            print(f"  [i] Instala rockyou.txt: sudo apt install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz")
    else:
        print(f"  Wordlist: {wordlist_path}")
    
    # Crear archivo de hashes temporal
    hash_file = create_hash_file(entries)
    print(f"  Archivo:  {hash_file}")
    
    # Elegir herramienta
    chosen = None
    reason = ""
    
    if hash_info['slow']:
        # Para hashes lentos: john es mejor en CPU que hashcat
        if tools.get("john"):
            chosen = "john"
            reason = "Hash lento → john es eficiente en CPU para bcrypt/scrypt"
        elif tools.get("hashcat"):
            chosen = "hashcat"
            reason = "Hash lento → hashcat (mejor con GPU)"
        elif tools.get("python-bcrypt") and hash_key == "bcrypt":
            chosen = "python"
            reason = "Fallback: Python + bcrypt (lento pero funciona)"
        else:
            chosen = "python"
            reason = "Sin herramientas externas, usando Python"
    else:
        # Para hashes rápidos: hashcat con GPU es mucho más rápido
        if tools.get("hashcat"):
            chosen = "hashcat"
            reason = "Hash rápido → hashcat aprovecha GPU"
        elif tools.get("john"):
            chosen = "john"
            reason = "Hash rápido → john en CPU"
        else:
            chosen = "python"
            reason = "Sin herramientas externas, usando Python"
    
    print(f"\n  Herramienta: {chosen.upper()}")
    print(f"  Razón:       {reason}")
    print(f"{'─' * 60}")
    
    if chosen == "john":
        extra = []
        if hash_info['slow']:
            # Para hashes lentos, usar reglas simples
            extra = ["--rules=Wordlist"]
        run_john(hash_file, wordlist=wordlist_path, 
                format_type=hash_info['john_format'], extra_args=extra)
    
    elif chosen == "hashcat":
        if hash_info['hashcat_mode']:
            run_hashcat(hash_file, mode=hash_info['hashcat_mode'],
                       wordlist=wordlist_path)
        else:
            print(f"  [!] Hashcat no soporta {hash_info['name']}, usando john...")
            if tools.get("john"):
                run_john(hash_file, wordlist=wordlist_path,
                        format_type=hash_info['john_format'])
    
    elif chosen == "python":
        python_fallback_crack(entries, hash_key, wordlist_path)
    
    # Limpiar
    try:
        os.unlink(hash_file)
    except Exception:
        pass


def python_fallback_crack(entries, hash_key, wordlist_path):
    """Crackeo con Python puro cuando no hay herramientas externas."""
    if not wordlist_path:
        print("  [!] Se necesita un wordlist. Usa: -w rockyou.txt")
        return
    
    print(f"\n  [*] Cargando wordlist...")
    passwords = []
    max_words = 50000 if hash_key in ("bcrypt", "sha512crypt", "sha256crypt") else 500000
    
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if word:
                passwords.append(word)
            if len(passwords) >= max_words:
                break
    
    print(f"  [*] Cargadas {len(passwords):,} contraseñas (límite: {max_words:,})")
    
    start = time.time()
    for entry in entries:
        user = entry['user']
        hash_str = entry['hash']
        print(f"\n  [*] Probando: {user}")
        
        if hash_key == "bcrypt":
            result, attempts = python_crack_bcrypt(hash_str.encode(), passwords)
        else:
            result, attempts = python_crack_generic(hash_str, hash_key, passwords)
        
        elapsed = time.time() - start
        if result:
            print(f"  [+] {user} -> {result} (intento #{attempts+1}, {elapsed:.1f}s)")
        else:
            print(f"  [-] {user} -> no encontrada ({attempts:,} intentos, {elapsed:.1f}s)")


# ─────────────────────────────────────────────────────────────
#  MODO PISTAS (con hints del profesor)
# ─────────────────────────────────────────────────────────────

def crack_with_hints(entries, tools, empieza=None, termina=None, contiene=None,
                     longitud=None, patron=None, charset="lower"):
    """Crackea usando pistas del profesor."""
    
    if not entries:
        print("  [!] No hay hashes para crackear")
        return
    
    # Identificar hash
    sample_hash = entries[0]["hash"]
    detected = identify_hash(sample_hash)
    if not detected:
        print(f"  [!] No se pudo identificar el hash")
        return
    
    hash_key, hash_info = detected[0]
    
    print(f"\n{'─' * 60}")
    print(f"  MODO PISTAS DEL PROFESOR")
    print(f"{'─' * 60}")
    print(f"  Hash:     {hash_info['name']}")
    print(f"  Usuarios: {', '.join(e['user'] for e in entries)}")
    
    # Construir patrón
    if patron:
        patterns = [patron]
        total = count_pattern_size(patron, CHARSET_MAP.get(charset, string.ascii_lowercase))
        print(f"  Patrón:   {patron}")
    else:
        if empieza: print(f"  Empieza:  '{empieza}'")
        if termina: print(f"  Termina:  '{termina}'")
        if contiene: print(f"  Contiene: '{contiene}'")
        if longitud: print(f"  Longitud: {longitud}")
        print(f"  Charset:  {charset}")
        
        patterns, charset, total = build_pattern_from_hints(
            longitud, empieza, termina, contiene, charset
        )
        
        if patterns is None:
            return
    
    print(f"  Total combinaciones: {total:,}")
    
    # Estimar tiempo
    if hash_info['slow']:
        speed = 20  # bcrypt ~20/s con john
        est_secs = total / speed
    else:
        speed = 100000  # hashes rápidos
        est_secs = total / speed
    
    if est_secs < 60:
        print(f"  Tiempo estimado:     ~{est_secs:.0f} segundos")
    elif est_secs < 3600:
        print(f"  Tiempo estimado:     ~{est_secs/60:.1f} minutos")
    else:
        print(f"  Tiempo estimado:     ~{est_secs/3600:.1f} horas ⚠")
        if est_secs > 7200:
            print(f"  [!] DEMASIADO TIEMPO - necesitas más pistas del profesor")
    
    print(f"{'─' * 60}")
    
    # Crear archivo de hashes
    hash_file = create_hash_file(entries)
    
    # Elegir método
    if tools.get("crunch") and tools.get("john") and total > 10000:
        # Usar crunch | john (más eficiente para grandes volúmenes)
        print(f"\n  [*] Usando crunch → john (eficiente por pipe)")
        for pat in patterns:
            crunch_tmpl = hints_to_crunch_template(pat)
            plen = len(pat)
            crunch_charset = CHARSET_MAP.get(charset, string.ascii_lowercase)
            run_crunch_to_john(plen, plen, crunch_charset, crunch_tmpl,
                              hash_file, hash_info['john_format'])
    
    elif tools.get("john"):
        # Generar wordlist temporal y usar john
        print(f"\n  [*] Generando wordlist y usando john...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='pistas_') as f:
            tmp_wl = f.name
            count = 0
            for pat in patterns:
                for pwd in generate_passwords_from_pattern(pat, charset):
                    f.write(pwd + '\n')
                    count += 1
                    if count % 100000 == 0:
                        print(f"\r  [.] Generadas {count:,}...", end="", flush=True)
            print(f"\r  [*] Generadas {count:,} contraseñas -> {tmp_wl}")
        
        run_john(hash_file, wordlist=tmp_wl, format_type=hash_info['john_format'])
        os.unlink(tmp_wl)
    
    elif tools.get("hashcat") and hash_info['hashcat_mode']:
        # Hashcat con máscara
        print(f"\n  [*] Usando hashcat con máscara...")
        # Convertir patrón a máscara hashcat
        # hashcat: ?l = lower, ?u = upper, ?d = digit, ?a = all
        hc_charset_map = {
            "lower": "?l", "upper": "?u", "digits": "?d",
            "lower+digits": "?1", "alpha": "?1",
        }
        hc_wild = hc_charset_map.get(charset, "?l")
        
        for pat in patterns:
            mask = ""
            for ch in pat:
                if ch in ('?', '*'):
                    mask += hc_wild
                elif ch == '#':
                    mask += "?d"
                else:
                    mask += ch
            
            extra = []
            if charset in ("lower+digits", "alpha"):
                extra = ["-1", CHARSET_MAP.get(charset, "?l?d")]
            
            run_hashcat(hash_file, mode=hash_info['hashcat_mode'],
                       mask=mask, extra_args=extra)
    
    else:
        # Python fallback
        print(f"\n  [*] Usando Python (sin herramientas externas)...")
        
        for entry in entries:
            user = entry['user']
            h = entry['hash']
            print(f"\n  [*] Atacando: {user}")
            
            found = False
            start = time.time()
            total_attempts = 0
            
            for pat in patterns:
                gen = generate_passwords_from_pattern(pat, charset)
                
                for pwd in gen:
                    total_attempts += 1
                    
                    try:
                        if hash_key == "bcrypt":
                            import bcrypt as bc
                            if bc.checkpw(pwd.encode('utf-8'), h.encode() if isinstance(h, str) else h):
                                elapsed = time.time() - start
                                print(f"\n  [+] ¡ENCONTRADA! {user} -> {pwd}")
                                print(f"      Intentos: {total_attempts:,} | Tiempo: {elapsed:.1f}s")
                                found = True
                                break
                        else:
                            import hashlib
                            computed = hashlib.new(hash_key, pwd.encode()).hexdigest()
                            if computed == h.lower():
                                elapsed = time.time() - start
                                print(f"\n  [+] ¡ENCONTRADA! {user} -> {pwd}")
                                print(f"      Intentos: {total_attempts:,} | Tiempo: {elapsed:.1f}s")
                                found = True
                                break
                    except Exception:
                        continue
                    
                    if total_attempts % 50 == 0:
                        elapsed = time.time() - start
                        speed = total_attempts / elapsed if elapsed > 0 else 0
                        print(f"\r  [.] {total_attempts:,} intentos | {elapsed:.1f}s | {speed:.1f} pwd/s | último: {pwd}", 
                              end="", flush=True)
                
                if found:
                    break
            
            if not found:
                elapsed = time.time() - start
                print(f"\n  [-] {user} -> no encontrada ({total_attempts:,} intentos, {elapsed:.1f}s)")
    
    # Limpiar
    try:
        os.unlink(hash_file)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  INTERFAZ DE LÍNEA DE COMANDOS
# ─────────────────────────────────────────────────────────────

def parse_args():
    """Parsea argumentos de línea de comandos."""
    
    parser = argparse.ArgumentParser(
        description="🔓 Hash Cracker Multi-Herramienta - Tarea de clase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════╗
║  EJEMPLOS RÁPIDOS PARA EL EXAMEN                            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  MODO AUTO (detecta hash y elige herramienta):               ║
║  python3 cracker.py auto -f shadow.txt                       ║
║  python3 cracker.py auto -f shadow.txt -w rockyou.txt        ║
║  python3 cracker.py auto -H '$2a$10$abc...'                  ║
║                                                              ║
║  IDENTIFICAR HASH (solo ver qué tipo es):                    ║
║  python3 cracker.py id -H '$6$salt$hash...'                  ║
║                                                              ║
║  CON PISTAS DEL PROFESOR:                                    ║
║  python3 cracker.py pistas -H '$2a$...' --empieza ab -n 6   ║
║  python3 cracker.py pistas -f h.txt --termina 23 -n 5       ║
║  python3 cracker.py pistas -H '$2a$...' --patron "ab???#"   ║
║                                                              ║
║  JOHN THE RIPPER directo:                                    ║
║  python3 cracker.py john -f shadow.txt -w rockyou.txt        ║
║                                                              ║
║  HASHCAT directo:                                            ║
║  python3 cracker.py hashcat -H hash -m 3200 -w rockyou.txt  ║
║                                                              ║
║  HYDRA (fuerza bruta servicios):                             ║
║  python3 cracker.py hydra -s ssh://10.0.0.1 -u root         ║
║                                                              ║
║  PATRONES:  ? = letra  # = dígito  * = alfanum              ║
║  Ejemplo:   "pa??##" = pa + 2 letras + 2 dígitos            ║
╚══════════════════════════════════════════════════════════════╝
"""
    )
    
    subparsers = parser.add_subparsers(dest="modo", help="Modo de operación")
    
    # ── Modo AUTO ──
    auto_p = subparsers.add_parser("auto", help="Detecta hash y elige la mejor estrategia")
    auto_input = auto_p.add_mutually_exclusive_group(required=True)
    auto_input.add_argument("-H", "--hash", help="Hash directo (entre comillas)")
    auto_input.add_argument("-f", "--file", help="Archivo con hashes (formato shadow o hash por línea)")
    auto_p.add_argument("-w", "--wordlist", help="Ruta al wordlist (auto-detecta si no se pone)")
    
    # ── Modo IDENTIFICAR ──
    id_p = subparsers.add_parser("id", help="Solo identificar el tipo de hash")
    id_input = id_p.add_mutually_exclusive_group(required=True)
    id_input.add_argument("-H", "--hash", help="Hash a identificar")
    id_input.add_argument("-f", "--file", help="Archivo con hashes")
    
    # ── Modo PISTAS ──
    pistas_p = subparsers.add_parser("pistas", help="Crackear con pistas del profesor")
    pistas_input = pistas_p.add_mutually_exclusive_group(required=True)
    pistas_input.add_argument("-H", "--hash", help="Hash directo")
    pistas_input.add_argument("-f", "--file", help="Archivo con hashes")
    pistas_p.add_argument("--empieza", help="La contraseña empieza por...")
    pistas_p.add_argument("--termina", help="La contraseña termina en...")
    pistas_p.add_argument("--contiene", help="La contraseña contiene...")
    pistas_p.add_argument("-n", "--longitud", type=int, help="Longitud exacta de la contraseña")
    pistas_p.add_argument("--patron", help="Patrón directo: ? = letra, # = dígito, * = alfanum")
    pistas_p.add_argument("--charset", default="lower", 
                          choices=list(CHARSET_MAP.keys()),
                          help="Conjunto de caracteres (default: lower)")
    pistas_p.add_argument("-u", "--user", help="Solo atacar este usuario (si hay varios)")
    
    # ── Modo JOHN ──
    john_p = subparsers.add_parser("john", help="Usar John the Ripper directamente")
    john_input = john_p.add_mutually_exclusive_group(required=True)
    john_input.add_argument("-H", "--hash", help="Hash directo")
    john_input.add_argument("-f", "--file", help="Archivo con hashes")
    john_p.add_argument("-w", "--wordlist", help="Wordlist")
    john_p.add_argument("--format", help="Formato de john (auto-detecta si no se pone)")
    john_p.add_argument("--rules", help="Reglas de john (ej: Wordlist, Jumbo)")
    john_p.add_argument("--extra", nargs="*", help="Argumentos extra para john")
    
    # ── Modo HASHCAT ──
    hc_p = subparsers.add_parser("hashcat", help="Usar Hashcat directamente")
    hc_input = hc_p.add_mutually_exclusive_group(required=True)
    hc_input.add_argument("-H", "--hash", help="Hash directo")
    hc_input.add_argument("-f", "--file", help="Archivo con hashes")
    hc_p.add_argument("-w", "--wordlist", help="Wordlist")
    hc_p.add_argument("-m", "--mode", help="Modo hashcat (auto-detecta si no se pone)")
    hc_p.add_argument("--mask", help="Máscara hashcat (ej: ?l?l?l?l?d?d)")
    hc_p.add_argument("--extra", nargs="*", help="Argumentos extra para hashcat")
    
    # ── Modo CRUNCH ──
    crunch_p = subparsers.add_parser("crunch", help="Generar passwords con crunch/patrón y crackear")
    crunch_input = crunch_p.add_mutually_exclusive_group(required=True)
    crunch_input.add_argument("-H", "--hash", help="Hash directo")
    crunch_input.add_argument("-f", "--file", help="Archivo con hashes")
    crunch_p.add_argument("--patron", required=True, help="Patrón: ? = letra, # = dígito")
    crunch_p.add_argument("--charset", default="lower", choices=list(CHARSET_MAP.keys()))
    
    # ── Modo HYDRA ──
    hydra_p = subparsers.add_parser("hydra", help="Fuerza bruta de servicios con Hydra")
    hydra_p.add_argument("-s", "--service", required=True, 
                         help="Servicio: protocolo://host[:puerto] (ej: ssh://10.0.0.1)")
    hydra_p.add_argument("-u", "--user", help="Usuario a atacar")
    hydra_p.add_argument("-U", "--userlist", help="Archivo con lista de usuarios")
    hydra_p.add_argument("-w", "--wordlist", help="Wordlist de contraseñas")
    hydra_p.add_argument("--extra", nargs="*", help="Argumentos extra para hydra")
    
    # ── Modo TOOLS ──
    subparsers.add_parser("tools", help="Mostrar herramientas disponibles y wordlists")
    
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
#  FUNCIONES AUXILIARES
# ─────────────────────────────────────────────────────────────

def get_entries_from_args(args):
    """Obtiene las entradas de hash desde los argumentos."""
    entries = []
    
    if hasattr(args, 'file') and args.file:
        entries = parse_shadow_file(args.file)
        if not entries:
            # Intentar como archivo de hashes simples (uno por línea)
            with open(args.file, 'r') as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            parts = line.split(':')
                            entries.append({"user": parts[0], "hash": parts[1], "full_line": line})
                        else:
                            entries.append({"user": f"hash_{i}", "hash": line, "full_line": line})
    
    elif hasattr(args, 'hash') and args.hash:
        h = args.hash.strip()
        if ':' in h:
            parts = h.split(':')
            entries.append({"user": parts[0], "hash": parts[1], "full_line": h})
        else:
            entries.append({"user": "target", "hash": h, "full_line": h})
    
    # Filtrar por usuario si se especificó
    if hasattr(args, 'user') and args.user:
        entries = [e for e in entries if e['user'] == args.user]
    
    return entries


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    
    if not args.modo:
        # Sin argumentos: mostrar ayuda interactiva
        print_interactive_help()
        return
    
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  HASH CRACKER MULTI-HERRAMIENTA                            ║")
    print("║  Seguridad Informática - Uso educativo                      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    
    # Detectar herramientas disponibles
    print(f"\n[*] Herramientas disponibles:")
    tools = check_tools()
    
    # ── MODO TOOLS ──
    if args.modo == "tools":
        print(f"\n[*] Wordlists encontradas:")
        wl = find_wordlist()
        if wl:
            for path, size in wl:
                print(f"  [✓] {path} ({size:.1f} MB)")
        else:
            print(f"  [!] No se encontraron wordlists")
            print(f"      Instala: sudo apt install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz")
        return
    
    # ── MODO ID ──
    if args.modo == "id":
        entries = get_entries_from_args(args)
        print(f"\n[*] Identificación de hashes:")
        for entry in entries:
            print(f"\n  Usuario: {entry['user']}")
            print(f"  Hash:    {entry['hash'][:60]}...")
            print_hash_info(entry['hash'])
        return
    
    # ── MODO AUTO ──
    if args.modo == "auto":
        entries = get_entries_from_args(args)
        wordlist = args.wordlist if hasattr(args, 'wordlist') else None
        print(f"\n[*] Hashes cargados: {len(entries)}")
        for e in entries:
            print(f"    {e['user']:15s} : {e['hash'][:40]}...")
            print_hash_info(e['hash'])
        auto_strategy(entries, tools, wordlist)
        return
    
    # ── MODO PISTAS ──
    if args.modo == "pistas":
        entries = get_entries_from_args(args)
        if not entries:
            print("[!] No se encontraron hashes")
            return
        
        print(f"\n[*] Hashes cargados: {len(entries)}")
        crack_with_hints(
            entries, tools,
            empieza=args.empieza,
            termina=args.termina,
            contiene=args.contiene,
            longitud=args.longitud,
            patron=args.patron,
            charset=args.charset,
        )
        return
    
    # ── MODO JOHN ──
    if args.modo == "john":
        if not tools.get("john"):
            print("\n[!] John the Ripper no está instalado")
            print("    sudo apt install john")
            return
        
        entries = get_entries_from_args(args)
        hash_file = args.file if args.file else create_hash_file(entries)
        
        # Auto-detectar formato si no se especificó
        fmt = args.format
        if not fmt and entries:
            detected = identify_hash(entries[0]['hash'])
            if detected:
                fmt = detected[0][1]['john_format']
                print(f"\n[*] Formato auto-detectado: {fmt}")
        
        wordlist = args.wordlist
        if not wordlist:
            wl = find_wordlist()
            if wl:
                wordlist = wl[0][0]
                print(f"[*] Wordlist auto-detectada: {wordlist}")
        
        extra = args.extra or []
        if args.rules:
            extra.append(f"--rules={args.rules}")
        
        run_john(hash_file, wordlist=wordlist, format_type=fmt, extra_args=extra)
        return
    
    # ── MODO HASHCAT ──
    if args.modo == "hashcat":
        if not tools.get("hashcat"):
            print("\n[!] Hashcat no está instalado")
            print("    sudo apt install hashcat")
            return
        
        entries = get_entries_from_args(args)
        hash_file = args.file if args.file else create_hash_file(entries)
        
        # Auto-detectar modo si no se especificó
        mode = args.mode
        if not mode and entries:
            detected = identify_hash(entries[0]['hash'])
            if detected and detected[0][1]['hashcat_mode']:
                mode = detected[0][1]['hashcat_mode']
                print(f"\n[*] Modo auto-detectado: -m {mode}")
        
        if not mode:
            print("[!] No se pudo detectar el modo. Usa -m MODO")
            return
        
        wordlist = args.wordlist
        if not wordlist and not args.mask:
            wl = find_wordlist()
            if wl:
                wordlist = wl[0][0]
        
        run_hashcat(hash_file, mode=mode, wordlist=wordlist,
                   mask=args.mask, extra_args=args.extra)
        return
    
    # ── MODO CRUNCH ──
    if args.modo == "crunch":
        entries = get_entries_from_args(args)
        if not entries:
            print("[!] No se encontraron hashes")
            return
        
        # Usar modo pistas con el patrón
        crack_with_hints(entries, tools, patron=args.patron, charset=args.charset)
        return
    
    # ── MODO HYDRA ──
    if args.modo == "hydra":
        if not tools.get("hydra"):
            print("\n[!] Hydra no está instalado")
            print("    sudo apt install hydra")
            return
        
        wordlist = args.wordlist
        if not wordlist:
            wl = find_wordlist()
            if wl:
                wordlist = wl[0][0]
        
        if not wordlist:
            print("[!] Se necesita un wordlist: -w rockyou.txt")
            return
        
        run_hydra(args.service, username=args.user, userlist=args.userlist,
                 wordlist=wordlist, extra_args=args.extra)
        return


def print_interactive_help():
    """Muestra ayuda interactiva cuando se ejecuta sin argumentos."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║  🔓 HASH CRACKER MULTI-HERRAMIENTA                         ║
║  Seguridad Informática - Tarea de clase                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  MODOS DISPONIBLES:                                          ║
║                                                              ║
║  auto    → Detecta hash y elige la mejor herramienta         ║
║  id      → Solo identificar qué tipo de hash es              ║
║  pistas  → Crackear con pistas del profesor                  ║
║  john    → Usar John the Ripper directamente                 ║
║  hashcat → Usar Hashcat directamente                         ║
║  crunch  → Generar passwords con patrón y crackear           ║
║  hydra   → Fuerza bruta de servicios (SSH, FTP, etc.)        ║
║  tools   → Ver herramientas y wordlists disponibles          ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  CHEATSHEET RÁPIDO PARA EXAMEN:                              ║
║                                                              ║
║  1) Identificar hash:                                        ║
║     python3 cracker.py id -H '$2a$10$abc...'                 ║
║                                                              ║
║  2) Crackear automático:                                     ║
║     python3 cracker.py auto -f shadow.txt                    ║
║                                                              ║
║  3) Con pistas del profe:                                    ║
║     python3 cracker.py pistas -H '$2a$...' \\                ║
║       --empieza "ab" --longitud 6                            ║
║                                                              ║
║  Usa: python3 cracker.py <modo> -h  para más ayuda          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
