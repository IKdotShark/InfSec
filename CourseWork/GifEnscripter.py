from PIL import Image, ImageSequence

def encode_gif(input_gif, output_gif, secret_data):
    # Открываем исходную гифку
    gif = Image.open(input_gif)
    frames = [frame.copy() for frame in ImageSequence.Iterator(gif)]

    # Преобразуем секретные данные в байты
    secret_bytes = secret_data.encode('utf-8')
    secret_length = len(secret_bytes)

    # Преобразуем первый кадр в RGB, если он в режиме P (палитра)
    if frames[0].mode == 'P':
        frames[0] = frames[0].convert('RGB')

    # Кодируем длину данных в первый кадр
    frames[0].putpixel((0, 0), (secret_length, secret_length, secret_length))

    # Кодируем данные в остальные кадры
    byte_index = 0
    for frame in frames[1:]:
        if byte_index >= secret_length:
            break
        # Преобразуем кадр в RGB, если он в режиме P (палитра)
        if frame.mode == 'P':
            frame = frame.convert('RGB')
        for x in range(frame.width):
            for y in range(frame.height):
                if byte_index >= secret_length:
                    break
                pixel = list(frame.getpixel((x, y)))
                pixel[0] = secret_bytes[byte_index]
                frame.putpixel((x, y), tuple(pixel))
                byte_index += 1

    # Сохраняем закодированную гифку
    frames[0].save(output_gif, save_all=True, append_images=frames[1:], loop=0, duration=gif.info['duration'])

def decode_gif(output_gif):
    gif = Image.open(output_gif)
    frames = [frame.copy() for frame in ImageSequence.Iterator(gif)]

    # Преобразуем первый кадр в RGB, если он в режиме P (палитра)
    if frames[0].mode == 'P':
        frames[0] = frames[0].convert('RGB')

    # Декодируем длину данных из первого кадра
    secret_length = frames[0].getpixel((0, 0))[0]

    # Декодируем данные из остальных кадров
    secret_bytes = bytearray()
    byte_index = 0
    for frame in frames[1:]:
        if byte_index >= secret_length:
            break
        # Преобразуем кадр в RGB, если он в режиме P (палитра)
        if frame.mode == 'P':
            frame = frame.convert('RGB')
        for x in range(frame.width):
            for y in range(frame.height):
                if byte_index >= secret_length:
                    break
                pixel = frame.getpixel((x, y))
                secret_bytes.append(pixel[0])
                byte_index += 1

    secret_data = secret_bytes.decode('utf-8')
    return secret_data


if __name__ == "__main__":
    input_gif = "test_sd.gif"
    output_gif = "output.gif"
    secret_data = "Qwerty123456"
    encode_gif(input_gif, output_gif, secret_data)
    print(f"Данные успешно закодированы в {output_gif}")
    secret_data = decode_gif(output_gif)
    print(f"Декодированные данные: {secret_data}")
