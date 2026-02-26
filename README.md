# Cracker de Hashes (bcrypt + rockyou.txt)

Este proyecto permite descifrar hashes bcrypt usando Python y la lista de contraseñas rockyou.txt. Es ideal para prácticas de seguridad, CTFs o tareas de clase.

## ¿Qué hace este script?
- Lee hashes bcrypt de varios usuarios.
- Usa multiprocessing para probar muchas contraseñas rápidamente.
- Utiliza las contraseñas más comunes de rockyou.txt (puedes ampliar el diccionario).

## ¿Cómo usarlo? (Guía para principiantes)

### 1. Descarga el diccionario rockyou.txt
- En Linux: `sudo apt install wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz`
- En Windows: busca "rockyou.txt" en Google y descárgalo (¡no lo subas a GitHub!).
- Coloca el archivo en la misma carpeta que el script.

### 2. Ejecuta el script

```bash
python crack_rockyou.py
```

### 3. ¿Qué verás?
- El script te dirá cuántas contraseñas va a probar y cuánto puede tardar.
- Si encuentra la contraseña de algún usuario, la mostrará en pantalla.
- Si no la encuentra, te sugerirá ampliar el diccionario o usar herramientas más potentes.

### 4. ¿Cómo añadir más contraseñas?
- Edita la variable `MAX_WORDS` en el script para probar más (o menos) palabras.
- Cuantas más palabras, más lento, pero más posibilidades de éxito.

### 5. ¿Qué hacer si no encuentra la contraseña?
- Prueba con un diccionario más grande.
- Usa herramientas como John the Ripper o Hashcat (más rápidas en Linux).

## Ejemplo de salida
```
============================================================
  CRACKER BCRYPT con rockyou.txt + multiprocessing
============================================================
[*] Cargando las top 10000 contraseñas de rockyou.txt...
[*] Cargadas: 10000 palabras
[*] CPUs disponibles: 8
[*] Tipo de hash: bcrypt ($2a$) cost factor 10
[*] Tiempo estimado por usuario: ~16.7 min
[*] Usando 8 procesos en paralelo para los 4 usuarios
[*] Tiempo estimado total: ~8.3 min
------------------------------------------------------------
  [+] root        -> cleopatra (intento #1234, 12.3s)
  [-] eduardo     -> NO encontrada (10000 intentos, 13.1s)
  ...

============================================================
  RESULTADOS FINALES
============================================================
  root        -> cleopatra
  eduardo     -> [NO ENCONTRADA]
  ...

Crackeadas: 1/4
Tiempo total: 13.1s

[i] Para las no encontradas, prueba aumentando MAX_WORDS
    o usando John the Ripper / Hashcat para mejor rendimiento
============================================================
```

## ¿Eres nuevo en Python?
- Solo necesitas tener Python 3 instalado.
- Instala la librería bcrypt si te da error:
  ```bash
  pip install bcrypt
  ```

## ¡No subas archivos grandes!
- No subas rockyou.txt ni otros diccionarios grandes a GitHub.
- Usa `.gitignore` para ignorarlos.

---

¡Listo! Así cualquier persona, aunque no sepa nada de seguridad, puede usar tu script para aprender y practicar. Si tienes dudas, abre un issue en el repo.
