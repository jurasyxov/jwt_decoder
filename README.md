## JWT Decoder (офлайн)

Многоязычная утилита для локального декодирования и анализа JWT (JSON Web Tokens).  
Работает полностью офлайн, не отправляет данные на внешние серверы, что гарантирует безопасность чувствительных токенов.

## Особенности
- Декодирование трёх частей JWT (Header, Payload, Signature) из Base64URL.
- Вывод заголовка и полезной нагрузки в удобочитаемом JSON-формате.
- Проверка времени истечения (exp) с выводом статуса (истёк / действителен).
- Верификация подписи с использованием HMAC (при указании секретного ключа) – офлайн.
- Чтение JWT из аргумента командной строки, из файла или stdin.
- Экспорт результата в формате JSON.
- Цветное оформление вывода (поддерживается в терминалах).
- Поддержка аргументов командной строки во всех реализациях.

## Установка и запуск
Для каждого языка требуются соответствующие инструменты и зависимости.

### Запуск на разных языках

1. **Python**  
   Установка: `pip install pyjwt colorama` (или использовать стандартные библиотеки)  
   Запуск: `python jwt_decoder.py <JWT> --key secret`

2. **JavaScript (Node.js)**  
   Установка: `npm install jsonwebtoken commander chalk`  
   Запуск: `node jwt_decoder.js <JWT> --key secret`

3. **Go**  
   Установка: модулей не требуется (стандартная библиотека + `golang-jwt/jwt`).  
   Запуск: `go run jwt_decoder.go <JWT> --key secret`

4. **Rust**  
   Добавьте `jsonwebtoken`, `serde`, `clap` в `Cargo.toml`.  
   Запуск: `cargo run -- <JWT> --key secret`

5. **Java**  
   Используйте `jjwt` (или `nimbus-jose-jwt`). Для простоты используем стандартные библиотеки для Base64 и JSON (Jackson/Gson).  
   Сборка: `javac -cp gson.jar:jjwt.jar JWTDecoder.java`  
   Запуск: `java -cp .;gson.jar;jjwt.jar JWTDecoder <JWT>`

6. **C# (.NET Core)**  
   Установка: `dotnet add package Newtonsoft.Json` и `System.IdentityModel.Tokens.Jwt`.  
   Запуск: `dotnet run -- <JWT> --key secret`

7. **C++ (Linux)**  
   Требуется библиотека `jwt-cpp` или реализация вручную. Используем `nlohmann/json` и `openssl` для HMAC.  
   Сборка: `g++ -std=c++11 -o jwt_decoder jwt_decoder.cpp -lssl -lcrypto -ljsoncpp`  
   Запуск: `./jwt_decoder <JWT> --key secret`

8. **Kotlin (JVM)**  
   Используйте `jjwt` и `gson`.  
   Сборка: `kotlinc -cp gson.jar:jjwt.jar JWTDecoder.kt`  
   Запуск: `kotlin -cp .;gson.jar;jjwt.jar JWTDecoderKt <JWT>`

## Использование

Общие аргументы командной строки:

- `token` (позиционный) – JWT-токен для декодирования.
- `--key <секрет>` – секретный ключ для проверки подписи (HMAC).
- `--file <путь>` – читать JWT из файла (вместо аргумента).
- `--json` – вывести результат в формате JSON.
- `--color` – принудительно включить цветной вывод.
- `--help` – справка.

Пример (Python):
```bash
python jwt_decoder.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c --key secret --json
Пример вывода (цветной):

text
Header:
  alg: HS256
  typ: JWT
Payload:
  sub: 1234567890
  name: John Doe
  iat: 1516239022
  exp: 1516242622
  [✓] Token is valid (exp: 2024-01-01 12:00:00)
Signature: SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
[✓] Signature verified
Структура репозитория
text
/
├── README.md
├── jwt_decoder.py
├── jwt_decoder.js
├── jwt_decoder.go
├── jwt_decoder.rs
├── JWTDecoder.java
├── JWTDecoder.cs
├── jwt_decoder.cpp
└── JWTDecoder.kt
Лицензия
MIT
