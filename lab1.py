import argparse
import getpass
from sympy import Integer


def get_alphabet_size(password):
    """
    Определяет мощность алфавита пароля.
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digits:
        size += 10
    if has_special:
        size += 33

    return size


def format_time(total_seconds):
    """
    Форматирует время в человекочитаемый вид (годы, месяцы, дни и т. д.).
    """
    years = total_seconds // (365 * 24 * 3600)
    total_seconds %= 365 * 24 * 3600
    months = total_seconds // (30 * 24 * 3600)
    total_seconds %= 30 * 24 * 3600
    days = total_seconds // (24 * 3600)
    total_seconds %= 24 * 3600
    hours = total_seconds // 3600
    total_seconds %= 3600
    minutes = total_seconds // 60
    seconds = total_seconds % 60

    return f"{years} лет, {months} месяцев, {days} дней, {hours} часов, {minutes} минут, {seconds} секунд"


def main():
    """
    Основная логика программы: расчет времени подбора пароля.
    """
    parser = argparse.ArgumentParser(description="Оценка времени подбора пароля")
    parser.add_argument("-s", "--secure", action="store_true", help="Скрытый ввод пароля")
    args = parser.parse_args()

    if args.secure:
        password = getpass.getpass("Введите пароль: ")
    else:
        password = input("Введите пароль: ")

    speed = Integer(input("Введите скорость перебора (паролей в секунду): "))
    attempts_before_pause = Integer(input("Введите количество неудачных попыток до паузы: "))
    pause_time = Integer(input("Введите время паузы (в секундах): "))

    alphabet_size = get_alphabet_size(password)
    total_combinations = Integer(alphabet_size) ** len(password)
    base_time_seconds = total_combinations // speed

    pause_count = (total_combinations - 1) // attempts_before_pause
    total_time_seconds = base_time_seconds + pause_count * pause_time

    print(f"\nМощность алфавита: {alphabet_size}")
    print(f"Общее количество возможных паролей: {total_combinations}")
    print(f"Примерное время подбора: {format_time(total_time_seconds)}")


if __name__ == "__main__":
    main()

"""
Запуск программы:
Обычный режим:
    python lab1.py

Режим скрытого ввода пароля:
    python lab1.py -s
    или
    python lab1.py --secure
"""
