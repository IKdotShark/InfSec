import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import Counter
import random
import math
import os
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Русский алфавит
ALPHABET = "абвгдежзийклмнопрстуфхцчшщъыьэюяё"


# ========== Caesar Cipher Functions ==========
def caesar_determine_key(cipher_text, ref_letter_freq):
    """Определение ключа шифра Цезаря на основе частотного анализа"""
    filtered = ''.join([ch.lower() for ch in cipher_text if ch.lower() in ALPHABET])
    if not filtered:
        return 0

    freq = get_letter_frequency(filtered)
    if not freq:
        return 0

    # Находим самые частые буквы
    most_freq_cipher = max(freq.items(), key=lambda x: x[1])[0]
    most_freq_ref = max(ref_letter_freq.items(), key=lambda x: x[1])[0]

    # Вычисляем сдвиг между ними
    idx_cipher = ALPHABET.index(most_freq_cipher)
    idx_ref = ALPHABET.index(most_freq_ref)

    return (idx_cipher - idx_ref + len(ALPHABET)) % len(ALPHABET)


def caesar_cipher(text, shift):
    """Шифрование/дешифрование Цезаря с заданным сдвигом"""
    result = []
    for ch in text:
        if ch.lower() not in ALPHABET:
            result.append(ch)
            continue

        is_upper = ch.isupper()
        idx = ALPHABET.index(ch.lower())
        new_idx = (idx + shift) % len(ALPHABET)
        new_char = ALPHABET[new_idx]
        result.append(new_char.upper() if is_upper else new_char)

    return ''.join(result)


# ========== Frequency Analysis Functions ==========
def get_letter_frequency(text):
    """Подсчет частоты букв в тексте"""
    filtered = [ch.lower() for ch in text if ch.lower() in ALPHABET]
    return Counter(filtered)


def get_bigram_frequency(text):
    """Подсчет частоты биграмм в тексте"""
    filtered = [ch.lower() for ch in text if ch.lower() in ALPHABET]
    bigrams = [''.join(filtered[i:i + 2]) for i in range(len(filtered) - 1)]
    return Counter(bigrams)


def get_top_n(dct, n):
    """Получение N самых частых элементов"""
    return dict(sorted(dct.items(), key=lambda x: -x[1])[:n])


# ========== Vigenere Cipher Functions ==========
def vigenere_determine_key_length(cipher_text, max_key_length=33):
    """Определение длины ключа для шифра Виженера"""
    filtered = [ch.lower() for ch in cipher_text if ch.lower() in ALPHABET]
    filtered = ''.join(filtered)

    best_ic = 0
    best_key_length = 1

    for key_len in range(1, max_key_length + 1):
        ic_sum = 0
        for i in range(key_len):
            subtext = filtered[i::key_len]
            ic_sum += calculate_ic(subtext)
        avg_ic = ic_sum / key_len

        if avg_ic > best_ic:
            best_ic = avg_ic
            best_key_length = key_len

    return best_key_length


def calculate_ic(text):
    """Вычисление индекса совпадений для текста"""
    freq = Counter(text)
    total = len(text)
    if total <= 1:
        return 0
    ic = sum(cnt * (cnt - 1) for cnt in freq.values())
    return ic / (total * (total - 1))


def vigenere_determine_key(cipher_text, key_length, ref_letter_freq, ref_bigram_freq):
    """Определение ключа Виженера"""
    filtered = [ch.lower() for ch in cipher_text if ch.lower() in ALPHABET]
    filtered = ''.join(filtered)
    key = []

    for i in range(key_length):
        subtext = filtered[i::key_length]
        shift = determine_shift_combined(subtext, ref_letter_freq, ref_bigram_freq)
        key.append(ALPHABET[shift])

    return ''.join(key)


def determine_shift_combined(subtext, ref_letter, ref_bigram, weight_letter=1, weight_bigram=1):
    """Определение сдвига с комбинированной метрикой"""
    best_score = math.inf
    best_shift = 0

    for shift in range(len(ALPHABET)):
        shifted = apply_shift(subtext, shift)
        letter_freq = get_letter_frequency(shifted)
        bigram_freq = get_bigram_frequency(shifted)

        letter_error = sum(abs(ref_letter.get(char, 0) - letter_freq.get(char, 0)) for char in ref_letter)
        bigram_error = sum(abs(ref_bigram.get(bg, 0) - bigram_freq.get(bg, 0)) for bg in ref_bigram)

        total_error = weight_letter * letter_error + weight_bigram * bigram_error

        if total_error < best_score:
            best_score = total_error
            best_shift = shift

    return best_shift


def apply_shift(text, shift):
    """Применение сдвига к тексту"""
    result = []
    for ch in text:
        idx = ALPHABET.index(ch)
        new_idx = (idx - shift) % len(ALPHABET)
        result.append(ALPHABET[new_idx])
    return ''.join(result)


def vigenere_cipher(text, key, alphabet, decrypt=False):
    """Шифрование/дешифрование Виженера"""
    key = key.lower()
    key_len = len(key)
    result = []
    key_idx = 0

    for ch in text:
        if ch.lower() not in alphabet:
            result.append(ch)
            continue

        is_upper = ch.isupper()
        text_idx = alphabet.index(ch.lower())
        key_char = key[key_idx % key_len]
        key_shift = alphabet.index(key_char)

        if decrypt:
            key_shift = -key_shift

        new_idx = (text_idx + key_shift) % len(alphabet)
        new_char = alphabet[new_idx]
        result.append(new_char.upper() if is_upper else new_char)
        key_idx += 1

    return ''.join(result)


def generate_alphabet(randomize=False):
    """Генерация алфавита (опционально с рандомизацией)"""
    alph = list(ALPHABET)
    if randomize:
        random.shuffle(alph)
    return ''.join(alph)


# ========== Main Application ==========
class FrequencyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Frequency Cryptanalysis")
        self.geometry("900x600")

        # Инициализация данных
        self.crypto_text = ""
        self.large_text = ""
        self.ref_letter_freq = {}
        self.ref_bigram_freq = {}

        # Инициализация графиков ДО создания виджетов
        self.fig_letter = Figure(figsize=(5, 4), dpi=100)
        self.fig_bigram = Figure(figsize=(5, 4), dpi=100)

        # Создание интерфейса
        self.create_widgets()

    def create_widgets(self):
        """Создание элементов интерфейса"""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        # Вкладка криптоанализа
        self.create_crypto_tab()

        # Вкладка анализа частот
        self.create_freq_tab()

        # Вкладка шифрования
        self.create_encrypt_tab()

    def create_crypto_tab(self):
        """Вкладка криптоанализа"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Криптоанализ")

        frame = ttk.Frame(tab)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Выбор режима
        mode_frame = ttk.Frame(frame)
        mode_frame.pack(fill='x', pady=5)
        ttk.Label(mode_frame, text="Режим криптоанализа:").pack(side='left')
        self.mode_combo = ttk.Combobox(mode_frame, values=["Цезарь", "Виженер"], width=25)
        self.mode_combo.current(0)
        self.mode_combo.pack(side='left', padx=5)

        # Загрузка файла
        file_frame = ttk.Frame(frame)
        file_frame.pack(fill='x', pady=5)
        ttk.Label(file_frame, text="Путь к файлу:").pack(side='left')
        self.crypto_path = ttk.Entry(file_frame, width=50)
        self.crypto_path.pack(side='left', padx=5)
        ttk.Button(file_frame, text="Загрузить", command=self.load_crypto_file).pack(side='left')

        # Кнопка анализа
        ttk.Button(frame, text="Выполнить", command=self.process_crypto).pack(pady=5)

        # Результаты
        self.crypto_result = tk.Text(frame, wrap=tk.WORD, height=15)
        scroll = ttk.Scrollbar(frame, command=self.crypto_result.yview)
        self.crypto_result.configure(yscrollcommand=scroll.set)
        self.crypto_result.pack(side='left', expand=True, fill='both')
        scroll.pack(side='right', fill='y')

    def create_freq_tab(self):
        """Вкладка анализа частот"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Анализ частот")

        frame = ttk.Frame(tab)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Загрузка файла
        file_frame = ttk.Frame(frame)
        file_frame.pack(fill='x', pady=5)
        ttk.Label(file_frame, text="Путь к большому тексту:").pack(side='left')
        self.large_text_path = ttk.Entry(file_frame, width=50)
        self.large_text_path.pack(side='left', padx=5)
        ttk.Button(file_frame, text="Загрузить", command=self.load_large_text).pack(side='left')

        # Графики
        chart_frame = ttk.Frame(frame)
        chart_frame.pack(expand=True, fill='both')

        # График букв
        self.letter_canvas = FigureCanvasTkAgg(self.fig_letter, master=chart_frame)
        self.letter_canvas.get_tk_widget().pack(side='left', expand=True, fill='both')

        # График биграмм
        self.bigram_canvas = FigureCanvasTkAgg(self.fig_bigram, master=chart_frame)
        self.bigram_canvas.get_tk_widget().pack(side='left', expand=True, fill='both')

        # Кнопка построения графиков
        ttk.Button(frame, text="Построить графики", command=self.draw_charts).pack(pady=5)

    def create_encrypt_tab(self):
        """Вкладка шифрования"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Шифрование")

        frame = ttk.Frame(tab)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Загрузка файла
        file_frame = ttk.Frame(frame)
        file_frame.pack(fill='x', pady=5)
        ttk.Label(file_frame, text="Путь к файлу:").pack(side='left')
        self.encrypt_path = ttk.Entry(file_frame, width=50)
        self.encrypt_path.pack(side='left', padx=5)
        ttk.Button(file_frame, text="Открыть файл", command=self.open_encrypt_file).pack(side='left')

        # Шифр Цезаря
        caesar_frame = ttk.Frame(frame)
        caesar_frame.pack(fill='x', pady=5)
        ttk.Label(caesar_frame, text="Ключ Цезаря:").pack(side='left')
        self.caesar_key = ttk.Entry(caesar_frame, width=30)
        self.caesar_key.pack(side='left', padx=5)
        ttk.Button(caesar_frame, text="Выполнить Цезаря", command=self.caesar_process).pack(side='left')

        # Шифр Виженера
        vigenere_frame = ttk.Frame(frame)
        vigenere_frame.pack(fill='x', pady=5)
        ttk.Label(vigenere_frame, text="Ключ Виженера:").pack(side='left')
        self.vigenere_key = ttk.Entry(vigenere_frame, width=30)
        self.vigenere_key.pack(side='left', padx=5)
        self.random_alphabet = tk.BooleanVar()
        ttk.Checkbutton(vigenere_frame, text="Рандомизировать алфавит", variable=self.random_alphabet).pack(side='left')
        ttk.Button(vigenere_frame, text="Выполнить Виженера", command=self.vigenere_process).pack(side='left')

        # Результаты
        self.encrypt_result = tk.Text(frame, wrap=tk.WORD, height=10)
        scroll = ttk.Scrollbar(frame, command=self.encrypt_result.yview)
        self.encrypt_result.configure(yscrollcommand=scroll.set)
        self.encrypt_result.pack(side='left', expand=True, fill='both')
        scroll.pack(side='right', fill='y')

    # ========== Event Handlers ==========
    def load_crypto_file(self):
        """Загрузка файла для криптоанализа"""
        path = filedialog.askopenfilename()
        if path:
            self.crypto_path.delete(0, tk.END)
            self.crypto_path.insert(0, path)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    self.crypto_text = f.read()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка загрузки файла: {str(e)}")

    def load_large_text(self):
        """Загрузка эталонного текста для анализа частот"""
        path = filedialog.askopenfilename()
        if path:
            self.large_text_path.delete(0, tk.END)
            self.large_text_path.insert(0, path)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    self.large_text = f.read()
                self.ref_letter_freq = get_letter_frequency(self.large_text)
                self.ref_bigram_freq = get_bigram_frequency(self.large_text)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка загрузки файла: {str(e)}")

    def process_crypto(self):
        """Обработка криптотекста"""
        if not self.crypto_text:
            if self.crypto_path.get():
                try:
                    with open(self.crypto_path.get(), 'r', encoding='utf-8') as f:
                        self.crypto_text = f.read()
                except:
                    messagebox.showwarning("Ошибка", "Не удалось загрузить текст")
                    return
            else:
                messagebox.showwarning("Ошибка", "Текст не загружен")
                return

        if not self.large_text:
            messagebox.showwarning("Ошибка", "Сначала загрузите большой текст для анализа частот")
            return

        mode = self.mode_combo.get()
        result = []

        if mode == "Цезарь":
            key = caesar_determine_key(self.crypto_text, self.ref_letter_freq)
            result.append(f"Предполагаемый ключ: {key}")
            decrypted = caesar_cipher(self.crypto_text, -key)
            result.append("\nРасшифрованный текст:\n" + decrypted[:500] + "...")

        elif mode == "Виженер":
            if self.random_alphabet.get():
                result.append("Рандомизация алфавита включена. Автоопределение ключа невозможно.")
            else:
                key_len = vigenere_determine_key_length(self.crypto_text)
                result.append(f"Длина ключа: {key_len}")
                key = vigenere_determine_key(self.crypto_text, key_len,
                                             self.ref_letter_freq, self.ref_bigram_freq)
                result.append(f"Предполагаемый ключ: {key}")
                alph = generate_alphabet(False)
                decrypted = vigenere_cipher(self.crypto_text, key, alph, True)
                result.append("\nРасшифрованный текст:\n" + decrypted[:500] + "...")

        self.crypto_result.delete(1.0, tk.END)
        self.crypto_result.insert(tk.END, '\n'.join(result))

    def draw_charts(self):
        """Построение графиков частот"""
        if not self.large_text:
            if self.large_text_path.get():
                try:
                    with open(self.large_text_path.get(), 'r', encoding='utf-8') as f:
                        self.large_text = f.read()
                    self.ref_letter_freq = get_letter_frequency(self.large_text)
                    self.ref_bigram_freq = get_bigram_frequency(self.large_text)
                except:
                    messagebox.showwarning("Ошибка", "Не удалось загрузить текст")
                    return
            else:
                messagebox.showwarning("Ошибка", "Сначала загрузите большой текст")
                return

        # Очищаем предыдущие графики
        self.fig_letter.clear()
        self.fig_bigram.clear()

        # График частот букв
        ax1 = self.fig_letter.add_subplot(111)
        letters = get_top_n(get_letter_frequency(self.large_text), 10)
        ax1.bar(letters.keys(), letters.values())
        ax1.set_title("Топ-10 букв")
        ax1.set_ylabel("Частота")

        # График частот биграмм
        ax2 = self.fig_bigram.add_subplot(111)
        bigrams = get_top_n(get_bigram_frequency(self.large_text), 10)
        ax2.bar(bigrams.keys(), bigrams.values())
        ax2.set_title("Топ-10 биграмм")
        ax2.set_ylabel("Частота")

        # Обновляем графики
        self.letter_canvas.draw()
        self.bigram_canvas.draw()

    def open_encrypt_file(self):
        """Открытие файла для шифрования"""
        path = filedialog.askopenfilename()
        if path:
            self.encrypt_path.delete(0, tk.END)
            self.encrypt_path.insert(0, path)

    def caesar_process(self):
        """Обработка шифра Цезаря"""
        path = self.encrypt_path.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Ошибка", "Файл не существует")
            return

        try:
            key = int(self.caesar_key.get())
        except:
            messagebox.showerror("Ошибка", "Ключ Цезаря должен быть целым числом")
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()

            if len(text) < 2000:
                messagebox.showwarning("Предупреждение", "Рекомендуется текст не менее 2000 символов")

            # Шифрование
            enc = caesar_cipher(text, key)

            # Дешифрование
            dec = caesar_cipher(enc, -key)

            # Сохранение результатов
            base = os.path.splitext(os.path.basename(path))[0]
            enc_path = f"encC_{base}.txt"
            dec_path = f"decC_{base}.txt"

            with open(enc_path, 'w', encoding='utf-8') as f:
                f.write(enc)

            with open(dec_path, 'w', encoding='utf-8') as f:
                f.write(dec)

            # Вывод результатов
            self.encrypt_result.delete(1.0, tk.END)
            self.encrypt_result.insert(tk.END, f"Оригинал: {text[:100]}...\n\n")
            self.encrypt_result.insert(tk.END, f"Зашифрованный: {enc[:100]}...\n\n")
            self.encrypt_result.insert(tk.END, f"Расшифрованный: {dec[:100]}...\n\n")
            self.encrypt_result.insert(tk.END, f"Файлы сохранены как:\n{enc_path}\n{dec_path}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка обработки файла: {str(e)}")

    def vigenere_process(self):
        """Обработка шифра Виженера"""
        path = self.encrypt_path.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Ошибка", "Файл не существует")
            return

        key = self.vigenere_key.get()
        if not key:
            messagebox.showerror("Ошибка", "Введите ключ Виженера")
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()

            if len(text) < 2000:
                messagebox.showwarning("Предупреждение", "Рекомендуется текст не менее 2000 символов")

            # Генерация алфавита
            randomize = self.random_alphabet.get()
            alphabet = generate_alphabet(randomize)

            # Шифрование
            enc = vigenere_cipher(text, key, alphabet)

            # Дешифрование
            dec = vigenere_cipher(enc, key, alphabet, decrypt=True)

            # Сохранение результатов
            base = os.path.splitext(os.path.basename(path))[0]
            enc_path = f"encV_{base}.txt"
            dec_path = f"decV_{base}.txt"

            with open(enc_path, 'w', encoding='utf-8') as f:
                f.write(enc)

            with open(dec_path, 'w', encoding='utf-8') as f:
                f.write(dec)

            # Генерация квадрата Виженера
            vigenere_square = self.generate_vigenere_square(alphabet, key, randomize)

            # Вывод результатов
            self.encrypt_result.delete(1.0, tk.END)
            self.encrypt_result.insert(tk.END, f"Оригинал: {text[:100]}...\n\n")
            self.encrypt_result.insert(tk.END, f"Зашифрованный: {enc[:100]}...\n\n")
            self.encrypt_result.insert(tk.END, f"Расшифрованный: {dec[:100]}...\n\n")
            self.encrypt_result.insert(tk.END, f"Файлы сохранены как:\n{enc_path}\n{dec_path}\n\n")
            self.encrypt_result.insert(tk.END, "Квадрат Виженера:\n" + vigenere_square)

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка обработки файла: {str(e)}")

    def generate_vigenere_square(self, alphabet, key, randomize_others=False):
        """Генерация квадрата Виженера"""
        sorted_alphabet = ''.join(sorted(alphabet))
        square = []

        for i, fixed_char in enumerate(sorted_alphabet):
            line = [fixed_char + " | "]
            remaining = [c for c in sorted_alphabet if c != fixed_char]

            if randomize_others:
                random.shuffle(remaining)
            else:
                shift = i % len(remaining)
                remaining = remaining[shift:] + remaining[:shift]

            line.extend(remaining)
            square.append(''.join(line))

        return '\n'.join(square)


# Запуск приложения
if __name__ == "__main__":
    app = FrequencyApp()
    app.mainloop()