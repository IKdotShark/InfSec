import os
import random

def read_file(filename):
    if not os.path.exists(filename):
        print(f"Ошибка: Файл {filename} не найден!")
        return None
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def write_file(filename, text):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(text)

def get_first_lines(text, n=5):
    lines = text.splitlines()
    return "\n".join(lines[:n])

# Цезарь
def caesar_encrypt(text, key):
    result = []
    # Определяем алфавиты латиницы и кириллицы
    LAT_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LAT_LOWER = "abcdefghijklmnopqrstuvwxyz"
    RUS_UPPER = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    RUS_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"

    for ch in text:
        if ch in LAT_UPPER:
            new_index = (LAT_UPPER.index(ch) + key) % len(LAT_UPPER)
            result.append(LAT_UPPER[new_index])
        elif ch in LAT_LOWER:
            new_index = (LAT_LOWER.index(ch) + key) % len(LAT_LOWER)
            result.append(LAT_LOWER[new_index])
        elif ch in RUS_UPPER:
            new_index = (RUS_UPPER.index(ch) + key) % len(RUS_UPPER)
            result.append(RUS_UPPER[new_index])
        elif ch in RUS_LOWER:
            new_index = (RUS_LOWER.index(ch) + key) % len(RUS_LOWER)
            result.append(RUS_LOWER[new_index])
        else:
            result.append(ch)
    return "".join(result)

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)

# Винжер
# Определяем кириллический алфавит
CYRILLIC_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

def vigenere_square(alphabet):
    size = len(alphabet)
    rows = []
    for i in range(size):
        row = alphabet[i:] + alphabet[:i]
        rows.append(row)
    return "\n".join(rows)

def vigenere_encrypt(text, key, alphabet):
    result = []
    key_length = len(key)
    alphabet_upper = alphabet.upper()  # Алфавит в верхнем регистре
    alphabet_lower = alphabet.lower()  # Алфавит в нижнем регистре

    for i, ch in enumerate(text):
        if ch.upper() in alphabet_upper:  # Проверяем, является ли символ буквой алфавита
            # Определяем, в каком регистре находится символ
            if ch.isupper():
                index = alphabet_upper.index(ch)
                key_char = key[i % key_length].upper()
                key_index = alphabet_upper.index(key_char)
                enc_index = (index + key_index) % len(alphabet_upper)
                result.append(alphabet_upper[enc_index])
            else:
                index = alphabet_lower.index(ch)
                key_char = key[i % key_length].lower()
                key_index = alphabet_lower.index(key_char)
                enc_index = (index + key_index) % len(alphabet_lower)
                result.append(alphabet_lower[enc_index])
        else:
            result.append(ch)  # Не изменяем символы, не входящие в алфавит
    return "".join(result)

def vigenere_decrypt(text, key, alphabet):
    result = []
    key_length = len(key)
    alphabet_upper = alphabet.upper()  # Алфавит в верхнем регистре
    alphabet_lower = alphabet.lower()  # Алфавит в нижнем регистре

    for i, ch in enumerate(text):
        if ch.upper() in alphabet_upper:  # Проверяем, является ли символ буквой алфавита
            # Определяем, в каком регистре находится символ
            if ch.isupper():
                index = alphabet_upper.index(ch)
                key_char = key[i % key_length].upper()
                key_index = alphabet_upper.index(key_char)
                dec_index = (index - key_index) % len(alphabet_upper)
                result.append(alphabet_upper[dec_index])
            else:
                index = alphabet_lower.index(ch)
                key_char = key[i % key_length].lower()
                key_index = alphabet_lower.index(key_char)
                dec_index = (index - key_index) % len(alphabet_lower)
                result.append(alphabet_lower[dec_index])
        else:
            result.append(ch)  # Не изменяем символы, не входящие в алфавит
    return "".join(result)

def caesar_cli():
    key = input("Введите ключ (целое число): ")
    try:
        key = int(key)
    except ValueError:
        print("Ошибка: Ключ должен быть целым числом!")
        return

    original = read_file("caesar_volume_test.txt")
    if original is None or len(original) < 2000:
        print("Ошибка: Файл Cesar.txt не найден или содержит менее 2000 символов!")
        return

    encrypted = caesar_encrypt(original, key)
    decrypted = caesar_decrypt(encrypted, key)

    write_file("encC_Cesar.txt", encrypted)
    write_file("decC_Cesar.txt", decrypted)

    print(" Исходный текст (первые 5 строк) ")
    print(get_first_lines(original))
    print("\n Зашифрованный текст (Цезарь) ")
    print(get_first_lines(encrypted))
    print("\n Расшифрованный текст (Цезарь) ")
    print(get_first_lines(decrypted))

def vigenere_cli():
    key = input("Введите ключ (текст): ").strip()
    if not key:
        print("Ошибка: Введите ключ!")
        return

    # Проверяем, что ключ состоит только из букв алфавита
    if not all(ch.upper() in CYRILLIC_ALPHABET for ch in key):
        print("Ошибка: Ключ должен содержать только кириллические символы!")
        return

    alphabet_option = input("Выберите вариант алфавита (1 - по порядку, 2 - случайным образом): ")
    if alphabet_option == "1":
        alphabet = CYRILLIC_ALPHABET
    elif alphabet_option == "2":
        alph_list = list(CYRILLIC_ALPHABET)
        random.shuffle(alph_list)
        alphabet = "".join(alph_list)
        print("Сгенерированный алфавит:", alphabet)
    else:
        print("Ошибка: Неверный выбор алфавита!")
        return

    print("\n----- Квадрат Виженера -----")
    square = vigenere_square(alphabet)
    print(square)

    original = read_file("Vinzher_volume_test.txt")
    if original is None or len(original) < 2000:
        print("Ошибка: Файл Vinzher_volume_test.txt не найден или содержит менее 2000 символов!")
        return

    # Шифрование и расшифрование с сохранением регистра
    encrypted = vigenere_encrypt(original, key, alphabet)
    decrypted = vigenere_decrypt(encrypted, key, alphabet)

    write_file("encV_Vishner.txt", encrypted)
    write_file("decV_Vishner.txt", decrypted)

    print("----- Исходный текст (первые 5 строк) -----")
    print(get_first_lines(original))
    print("\n----- Зашифрованный текст -----")
    print(get_first_lines(encrypted))
    print("\n----- Расшифрованный текст -----")
    print(get_first_lines(decrypted))

def main():
    while True:
        print("\nВыберите метод:")
        print("1. Метод Цезаря")
        print("2. Метод Виженера")
        print("3. Выход")
        choice = input("Ваш выбор: ")

        if choice == "1":
            caesar_cli()
        elif choice == "2":
            vigenere_cli()
        elif choice == "3":
            break
        else:
            print("Ошибка: Неверный выбор!")

if __name__ == "__main__":
    main()