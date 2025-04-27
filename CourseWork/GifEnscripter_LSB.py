from PIL import Image
import numpy as np


def lsb_encode(image_path, secret_message, output_path):
    # Открываем GIF-файл
    gif = Image.open(image_path)

    # Преобразуем GIF в массив numpy (приводим к RGB при необходимости)
    frames = []
    try:
        while True:
            frame = gif.copy()
            if frame.mode != 'RGB':
                frame = frame.convert('RGB')
            frames.append(np.array(frame))
            gif.seek(len(frames))
    except EOFError:
        pass

    # Сохраняем длину сообщения (количество символов)
    # 1. Преобразуем длину сообщения в 32-битное двоичное число
    secret_length = len(secret_message)
    length_info = format(secret_length, '032b')

    # Преобразуем сообщение в двоичный формат (8 бит на символ)
    secret_message_bin = ''.join(format(ord(c), '08b') for c in secret_message)

    # Добавляем информацию о длине перед сообщением
    full_message_bin = length_info + secret_message_bin
    message_length = len(full_message_bin)

    # Проверяем, достаточно ли места
    total_pixels = sum(frame.shape[0] * frame.shape[1] for frame in frames)
    if message_length > total_pixels * 3:
        raise ValueError("Сообщение слишком длинное для данного GIF-файла.")

    # Встраиваем сообщение
    message_index = 0
    for frame in frames:
        for i in range(frame.shape[0]):
            for j in range(frame.shape[1]):
                for k in range(3):
                    if message_index < message_length:
                        # Закодировать бит в LSB канала
                        frame[i, j, k] = (frame[i, j, k] & 0xFE) | int(full_message_bin[message_index])
                        message_index += 1
                    else:
                        break
                if message_index >= message_length:
                    break
            if message_index >= message_length:
                break
        if message_index >= message_length:
            break

    # Сохраняем результат
    frames_pil = [Image.fromarray(f) for f in frames]
    frames_pil[0].save(output_path, save_all=True, append_images=frames_pil[1:], loop=0, duration=gif.info['duration'])


def lsb_decode(image_path):
    # Открываем GIF-файл
    gif = Image.open(image_path)

    # Преобразуем GIF в массив numpy (приводим к RGB при необходимости)
    frames = []
    try:
        while True:
            frame = gif.copy()
            if frame.mode != 'RGB':
                frame = frame.convert('RGB')
            frames.append(np.array(frame))
            gif.seek(len(frames))
    except EOFError:
        pass

    # Извлекаем все биты из LSB
    binary_data = []
    for frame in frames:
        for i in range(frame.shape[0]):
            for j in range(frame.shape[1]):
                for k in range(3):
                    binary_data.append(str(frame[i, j, k] & 1))

    # Считываем первые 32 бита как длину сообщения
    length_bits = ''.join(binary_data[:32])
    secret_length = int(length_bits, 2)

    # Считываем следующие (secret_length * 8) бит как реальное сообщение
    start = 32
    end = 32 + secret_length * 8
    message_bits = ''.join(binary_data[start:end])

    # Преобразуем двоичные данные в строку
    decoded_chars = [
        chr(int(message_bits[i:i + 8], 2)) for i in range(0, len(message_bits), 8)
    ]
    return ''.join(decoded_chars)


if __name__ == '__main__':
    secret_message = "password"
    input_gif = "test_sd.gif"
    output_gif = "output.gif"

    # Шифрование
    lsb_encode(input_gif, secret_message, output_gif)

    # Дешифрование
    decoded_message = lsb_decode(output_gif)
    print("Decoded message:", decoded_message)