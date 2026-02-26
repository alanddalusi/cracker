#!/usr/bin/env python3
"""
Cracker de hashes bcrypt por diccionario.
Tarea de clase - uso educativo.
"""
import bcrypt
import time
import sys

# Hashes extraídos del archivo shadow
USERS = {
    "root":    "$2a$10$og/Yjq7B5iYkj0vxMqtiAukrC0fFc7Q9oXKGZAjr.PUVJ3dUMP.3u",
    "eduardo": "$2a$10$JZjkKeD5600KQiUG0fHq3udcLKcoY19597vYjSVq/AMQ2i4.S7W/6",
    "laura":   "$2a$10$5mf8SVHUg1tSw6c.fpgkSOv4y/rjoC.oO5iYKCafSX1fbeW1PYctG",
    "jose":    "$2a$10$roLcBYMh78zySl18hAStdeIH9dYvxkn0LqNoBsJ5iUldWmZ6JB036",
}

# Diccionario amplio de contraseñas comunes (Top passwords + variantes españolas)
WORDLIST = [
    # Top 100 contraseñas más comunes
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "minemine", "passwd",
    "admin", "administrator", "root", "toor", "changeme",
    "welcome", "p@ssw0rd", "passw0rd", "password1", "password123",
    # Contraseñas en español comunes
    "contraseña", "contrasena", "hola", "hola123", "america",
    "estrella", "miguel", "carlos", "garcia", "martinez",
    "lopez", "rodriguez", "fernandez", "gonzalez", "sanchez",
    "perez", "martin", "gomez", "ruiz", "diaz",
    "hernandez", "jimenez", "moreno", "alvarez", "romero",
    "alonso", "gutierrez", "navarro", "torres", "dominguez",
    "vazquez", "ramos", "gil", "ramirez", "serrano",
    "blanco", "molina", "morales", "suarez", "ortega",
    "delgado", "castro", "ortiz", "rubio", "marin",
    "sanz", "iglesias", "nuñez", "medina", "garrido",
    # Nombres comunes como contraseñas
    "jose", "jose123", "jose1234", "eduardo", "eduardo123",
    "laura", "laura123", "laura1234", "root123", "root1234",
    "maria", "maria123", "antonio", "antonio123", "manuel",
    "manuel123", "francisco", "francisco123", "david", "david123",
    "juan", "juan123", "javier", "javier123", "pedro",
    "pedro123", "angel", "angel123", "pablo", "pablo123",
    "rafael", "rafael123", "fernando", "fernando123", "luis",
    "luis123", "alberto", "alberto123", "alejandro", "alejandro123",
    "carmen", "carmen123", "ana", "ana123", "rosa", "rosa123",
    "elena", "elena123", "lucia", "lucia123", "marta", "marta123",
    "isabel", "isabel123", "sara", "sara123", "paula", "paula123",
    # Patrones de teclado
    "qwerty123", "asdf1234", "zxcvbnm123", "1q2w3e4r", "q1w2e3r4",
    "1q2w3e", "qwe123", "asd123", "zxc123",
    # Años y fechas comunes
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "1990", "1991", "1992", "1993", "1994", "1995", "1996",
    "1997", "1998", "1999", "2001", "2002", "2003", "2004",
    "2005", "2006", "2007", "2008", "2009", "2010",
    # Contraseñas con patrones simples
    "abcdef", "abcd1234", "abc1234", "aaa111", "aaaa1111",
    "test", "test123", "test1234", "guest", "guest123",
    "user", "user123", "usuario", "usuario123",
    "linux", "linux123", "ubuntu", "ubuntu123",
    "server", "server123", "security", "security123",
    # Más contraseñas comunes de listas de seguridad
    "letmein", "login", "hello", "charlie", "donald",
    "loveme", "michael1", "jordan23", "access14",
    "mustang1", "shadow1", "master1", "michael!", "trustno1",
    "abc", "abcabc", "4321", "54321", "pass123",
    "Password", "Password1", "Password123", "Pa$$w0rd",
    "tequiero", "teamo", "amigo", "amiga", "familia",
    "espana", "españa", "madrid", "barcelona", "sevilla",
    "valencia", "malaga", "bilbao", "zaragoza", "murcia",
    # Contraseñas de rockyou comunes adicionales
    "babygirl", "lovely", "monkey1", "monkey123",
    "princess1", "iloveu", "soccer1", "blink182",
    "whatever", "nicole1", "daniel1", "babygirl1",
    "butterfly", "purple", "tigger1", "jessica1",
    "soccer12", "babygurl", "friends", "butterfly1",
    "michael7", "junior", "lovely1", "iloveyou1",
    "soccer2", "iloveyou2", "0123456789", "password12",
    "secret", "secret123", "qwerty1", "passpass",
    # Más variantes con nombres de usuarios del shadow
    "Root", "Root123", "Root1234", "r00t", "r00t123",
    "Eduardo", "Eduardo123", "Eduardo1234", "edu", "edu123",
    "Laura", "Laura123", "Laura1234", "lau", "lau123",
    "Jose", "Jose123", "Jose1234", "jos", "jos123",
    "jose1", "eduardo1", "laura1", "root1",
    "jose12", "eduardo12", "laura12", "root12",
    # Contraseñas de seguridad simples
    "seguridad", "clave", "clave123", "acceso", "acceso123",
    "entrada", "sistema", "sistema123", "admin123", "admin1234",
    "administrador", "informatica", "internet", "internet123",
    "computer1", "network", "network1",
]

def crack_hash(username, hash_str, wordlist):
    """Intenta crackear un hash bcrypt con un diccionario."""
    hash_bytes = hash_str.encode('utf-8')
    
    for i, password in enumerate(wordlist):
        try:
            if bcrypt.checkpw(password.encode('utf-8'), hash_bytes):
                return password, i + 1
        except Exception:
            continue
    
    return None, len(wordlist)

def main():
    print("=" * 60)
    print("  CRACKER DE HASHES BCRYPT - Tarea de clase")
    print("=" * 60)
    print(f"\nUsuarios a crackear: {len(USERS)}")
    print(f"Palabras en diccionario: {len(WORDLIST)}")
    print(f"Tipo de hash: bcrypt ($2a$) con cost factor 10")
    print(f"\nNOTA: bcrypt es lento por diseño (~100ms por intento)")
    print(f"Tiempo estimado máximo: ~{len(WORDLIST) * len(USERS) * 0.1 / 60:.1f} minutos")
    print("-" * 60)
    
    results = {}
    total_start = time.time()
    
    for username, hash_str in USERS.items():
        print(f"\n[*] Crackeando: {username}")
        print(f"    Hash: {hash_str[:30]}...")
        start = time.time()
        
        password, attempts = crack_hash(username, hash_str, WORDLIST)
        elapsed = time.time() - start
        
        if password:
            print(f"    [+] ¡ENCONTRADA! -> {password}")
            print(f"    Intentos: {attempts} | Tiempo: {elapsed:.1f}s")
            results[username] = password
        else:
            print(f"    [-] No encontrada en el diccionario")
            print(f"    Intentos: {attempts} | Tiempo: {elapsed:.1f}s")
            results[username] = None
    
    total_elapsed = time.time() - total_start
    
    print("\n" + "=" * 60)
    print("  RESULTADOS FINALES")
    print("=" * 60)
    
    cracked = 0
    for username, password in results.items():
        if password:
            print(f"  {username:12s} -> {password}")
            cracked += 1
        else:
            print(f"  {username:12s} -> [NO ENCONTRADA]")
    
    print(f"\n  Crackeadas: {cracked}/{len(USERS)}")
    print(f"  Tiempo total: {total_elapsed:.1f}s")
    print("=" * 60)

if __name__ == "__main__":
    main()
