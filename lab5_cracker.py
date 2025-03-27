import sys
import bcrypt
import psycopg2
import re
import time
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QListWidget, QGroupBox, QFormLayout, QInputDialog, QListWidgetItem, QCheckBox, QFileDialog, QProgressBar
)
from PySide6.QtGui import QIcon
from itertools import product
import string

# Конфигурация БД
DB_CONFIG = {
    "dbname": "Auth",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def connect_db():
    conn = psycopg2.connect(**DB_CONFIG)
    if hasattr(QApplication.instance(), 'active_window') and isinstance(QApplication.instance().active_window, LoginWindow):
        QApplication.instance().active_window.register_db_connection(conn)
    return conn

def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return False
    return True

def validate_password(password, username):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
    SELECT require_special_chars, require_uppercase, 
           require_lowercase, require_digits 
    FROM users 
    WHERE username = %s
    """, (username,))
    restrictions = cur.fetchone()
    cur.close()
    conn.close()

    # Если ограничения не заданы (все False), пароль может быть любым
    if not restrictions or all(not restriction for restriction in restrictions):
        return True, "Password is valid."

    require_special_chars, require_uppercase, require_lowercase, require_digits = restrictions

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if require_uppercase and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."

    if require_lowercase and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."

    if require_digits and not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."

    if require_special_chars and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."

    return True, "Password is valid."

def show_error(message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("Error")
    msg.setInformativeText(message)
    msg.setWindowTitle("Error")
    msg.exec_()

def show_info(message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText("Info")
    msg.setInformativeText(message)
    msg.setWindowTitle("Info")
    msg.exec_()

# Создание таблицы пользователей
def init_db():
    """
    Инициализация базы данных: создание таблиц и начальных данных.
    Автоматически закрывает соединения даже при возникновении ошибок.
    """
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # Создаем таблицу users с полным набором параметров
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 32),
                password TEXT,
                email TEXT,
                cn TEXT,
                description TEXT,
                phonenumber TEXT,
                is_admin BOOLEAN DEFAULT FALSE NOT NULL,
                is_blocked BOOLEAN DEFAULT FALSE NOT NULL,
                failed_attempts INTEGER DEFAULT 0 NOT NULL,
                max_attempts INTEGER DEFAULT 3 NOT NULL,
                require_special_chars BOOLEAN DEFAULT FALSE,
                require_uppercase BOOLEAN DEFAULT FALSE,
                require_lowercase BOOLEAN DEFAULT FALSE,
                require_digits BOOLEAN DEFAULT FALSE
            )
        """)

        # Добавляем колонки для ограничений пароля, если они не существуют
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS require_special_chars BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS require_uppercase BOOLEAN DEFAULT TRUE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS require_lowercase BOOLEAN DEFAULT TRUE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS require_digits BOOLEAN DEFAULT TRUE;")

        # Проверяем, существует ли пользователь ADMIN
        cur.execute("SELECT * FROM users WHERE username = 'ADMIN'")
        if not cur.fetchone():
            # Хэшируем пароль для ADMIN
            hashed_pw = bcrypt.hashpw(b"ADMIN", bcrypt.gensalt()).decode()
            # Создаем пользователя ADMIN
            cur.execute("""
                INSERT INTO users (username, password, is_admin) 
                VALUES (%s, %s, %s)
            """, ("ADMIN", hashed_pw, True))

        conn.commit()

    except Exception as e:
        print(f"Error initializing database: {e}")
        if conn:
            conn.rollback()
        raise  # Пробрасываем исключение дальше для обработки на уровне приложения

    finally:
        # Гарантированное закрытие ресурсов
        if cur:
            try:
                cur.close()
            except Exception as e:
                print(f"Error closing cursor: {e}")

        if conn and not conn.closed:
            try:
                conn.close()
            except Exception as e:
                print(f"Error closing connection: {e}")

class PasswordCrackerWindow(QWidget):
    def __init__(self, login_window):
        super().__init__()
        self.login_window = login_window
        self.setWindowTitle("Password Cracker")
        self.setGeometry(300, 300, 500, 400)
        layout = QVBoxLayout()

        # Кнопки для выбора метода подбора
        self.brut_btn = QPushButton("Brut")
        self.brut_btn.clicked.connect(self.start_brut_force)
        layout.addWidget(self.brut_btn)

        self.dict_btn = QPushButton("Brut by Dictionary")
        self.dict_btn.clicked.connect(self.start_dictionary_attack)
        layout.addWidget(self.dict_btn)

        # Параметры для Brut
        self.brut_options = QGroupBox("Brut Options")
        brut_layout = QVBoxLayout()

        self.rus_check = QCheckBox("Russian Letters")
        brut_layout.addWidget(self.rus_check)

        self.latin_check = QCheckBox("Latin Letters")
        brut_layout.addWidget(self.latin_check)

        self.digits_check = QCheckBox("Digits")
        brut_layout.addWidget(self.digits_check)

        self.special_check = QCheckBox("Special Characters")
        brut_layout.addWidget(self.special_check)

        self.upper_check = QCheckBox("Uppercase")
        brut_layout.addWidget(self.upper_check)

        self.lower_check = QCheckBox("Lowercase")
        brut_layout.addWidget(self.lower_check)

        self.min_length_input = QLineEdit()
        self.min_length_input.setPlaceholderText("Min password length")
        brut_layout.addWidget(self.min_length_input)

        self.length_input = QLineEdit()
        self.length_input.setPlaceholderText("Max password length")
        brut_layout.addWidget(self.length_input)

        self.brut_options.setLayout(brut_layout)
        layout.addWidget(self.brut_options)

        # Прогресс-бар и метка для вывода скорости
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.speed_label = QLabel("Speed: 0 attempts/sec")
        layout.addWidget(self.speed_label)

        self.setLayout(layout)

    def start_brut_force(self):
        """
        Запуск полного перебора паролей.
        """
        chars = ""
        if self.rus_check.isChecked():
            chars += "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
        if self.latin_check.isChecked():
            if self.upper_check.isChecked():
                chars += string.ascii_uppercase
            if self.lower_check.isChecked():
                chars += string.ascii_lowercase
        if self.digits_check.isChecked():
            chars += string.digits
        if self.special_check.isChecked():
            chars += string.punctuation

        if not chars:
            QMessageBox.warning(self, "Error", "No characters selected for bruteforce!")
            return

        min_length = int(self.min_length_input.text()) if self.min_length_input.text() else 1
        max_length = int(self.length_input.text())
        self.brut_force(chars, min_length, max_length)

    def brut_force(self, chars, min_length, max_length):
        start_time = time.time()
        attempts = 0
        found = False

        for length in range(min_length, max_length + 1):
            for attempt in product(chars, repeat=length):
                if found:
                    return

                password = ''.join(attempt)
                attempts += 1

                # Обновляем GUI
                elapsed_time = time.time() - start_time
                speed = attempts / elapsed_time if elapsed_time > 0 else 0
                self.speed_label.setText(f"Speed: {speed:.2f} attempts/sec")
                progress_value = int(((length - min_length) / (max_length - min_length + 1)) * 100)
                self.progress_bar.setValue(progress_value)

                # Пробуем войти
                self.login_window.password_input.setText(password)
                if self.login_window.handle_login():  # Если вход успешен
                    QMessageBox.information(self, "Success", f"Password found: {password}")
                    found = True
                    return  # Выходим после успешного входа

                QApplication.processEvents()

        if not found:
            QMessageBox.information(
                self,
                "Brute-force completed",
                f"Password not found with given parameters\n"
                f"Total attempts: {attempts}"
            )

    def start_dictionary_attack(self):
        """
        Запуск подбора пароля по словарю.
        """
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Dictionary File", "", "Text Files (*.txt)")
        if file_name:
            self.dictionary_attack(file_name)

    def dictionary_attack(self, file_name):
        try:
            with open(file_name, 'r', encoding='utf-8') as file:
                dictionary = [line.strip() for line in file if line.strip()]
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read dictionary file: {e}")
            return

        start_time = time.time()
        attempts = 0
        found = False

        for word in dictionary:
            if found:
                break

            # Определяем язык слова (русский или английский)
            is_russian = any(
                cyrillic in word for cyrillic in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ')

            if is_russian:
                # Для русского слова пробуем только его английский вариант
                password = self.translate_to_english_layout(word)
                variants = [password]
            else:
                # Для английского слова пробуем как есть
                variants = [word]

            # Добавляем варианты регистра
            variants += [v.lower() for v in variants] + [v.upper() for v in variants]
            variants = list(set(variants))  # Удаляем дубликаты

            for password in variants:
                if found:
                    break

                attempts += 1

                # Обновляем GUI
                elapsed_time = time.time() - start_time
                speed = attempts / elapsed_time if elapsed_time > 0 else 0
                self.speed_label.setText(f"Speed: {speed:.2f} attempts/sec")
                self.progress_bar.setValue(int((attempts / len(dictionary)) * 100))

                # Пробуем войти
                self.login_window.password_input.setText(password)
                if self.login_window.handle_login():
                    QMessageBox.information(self, "Success", f"Password found: {password}")
                found = True
                return

                QApplication.processEvents()

        if not found:
            QMessageBox.information(
                self,
                "Dictionary attack completed",
                f"Password not found in dictionary\n"
                f"Total attempts: {attempts}"
            )

    def translate_to_english_layout(self, password):
        """
        Переводит пароль, набранный в русской раскладке, в английскую раскладку.
        """
        russian_to_english = {
            'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y',
            'г': 'u', 'ш': 'i', 'щ': 'o', 'з': 'p', 'х': '[', 'ъ': ']',
            'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f', 'п': 'g', 'р': 'h',
            'о': 'j', 'л': 'k', 'д': 'l', 'ж': ';', 'э': "'", 'я': 'z',
            'ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n', 'ь': 'm',
            'б': ',', 'ю': '.', 'ё': '`',
            'Й': 'Q', 'Ц': 'W', 'У': 'E', 'К': 'R', 'Е': 'T', 'Н': 'Y',
            'Г': 'U', 'Ш': 'I', 'Щ': 'O', 'З': 'P', 'Х': '{', 'Ъ': '}',
            'Ф': 'A', 'Ы': 'S', 'В': 'D', 'А': 'F', 'П': 'G', 'Р': 'H',
            'О': 'J', 'Л': 'K', 'Д': 'L', 'Ж': ':', 'Э': '"', 'Я': 'Z',
            'Ч': 'X', 'С': 'C', 'М': 'V', 'И': 'B', 'Т': 'N', 'Ь': 'M',
            'Б': '<', 'Ю': '>', 'Ё': '~'
        }
        translated = []
        for char in password:
            if char in russian_to_english:
                translated.append(russian_to_english[char])
            else:
                translated.append(char)
        return ''.join(translated)

    def closeEvent(self, event):
        if hasattr(self, 'login_window'):
            self.login_window.close_all_db_connections()
        event.accept()

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setGeometry(300, 300, 300, 150)
        layout = QVBoxLayout()

        # Поле для ввода username (задизейблено)
        self.username_input = QLineEdit("ADMIN")
        self.username_input.setDisabled(True)
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username_input)

        # Поле для ввода пароля
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)

        # Кнопка для открытия окна Password Cracker
        self.cracker_btn = QPushButton("Open Password Cracker")
        self.cracker_btn.clicked.connect(self.open_cracker)
        layout.addWidget(self.cracker_btn)

        # Флаг для отслеживания успешного входа
        self.is_logged_in = False
        self.login_attempts = 0
        self.setLayout(layout)
        self.db_connections = []

    def register_db_connection(self, conn):
        """Регистрируем новое соединение для последующего закрытия"""
        self.db_connections.append(conn)
        return conn

    def closeEvent(self, event):
        """Переопределяем метод закрытия окна"""
        self.close_all_db_connections()
        event.accept()

    def close_all_db_connections(self):
        """Закрываем все зарегистрированные соединения с БД"""
        for conn in self.db_connections:
            try:
                if conn and not conn.closed:
                    conn.close()
            except Exception as e:
                print(f"Error closing DB connection: {e}")
        self.db_connections.clear()

    def open_cracker(self):
        """
        Открывает окно Password Cracker.
        """
        self.cracker_window = PasswordCrackerWindow(self)
        self.cracker_window.show()

    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            return False

        conn = None
        cur = None
        try:
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("""
                SELECT password, is_blocked, max_attempts 
                FROM users 
                WHERE username = %s
            """, (username,))
            user = cur.fetchone()

            if not user:
                return False

            hashed_pw, is_blocked, max_attempts = user

            if is_blocked:
                show_error("Account is blocked!")
                return False

            # Проверяем пароль
            if bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8')):
                self.is_logged_in = True
                self.login_attempts = 0

                # Открываем соответствующую панель
                if username == "ADMIN":
                    self.open_admin_panel(username)
                else:
                    self.open_user_panel(username)
                return True
            else:
                self.login_attempts += 1
                if self.login_attempts >= max_attempts:
                    cur.execute("UPDATE users SET is_blocked = TRUE WHERE username = %s", (username,))
                    conn.commit()
                    show_error("Too many failed attempts! Account blocked.")
                return False

        except Exception as e:
            print(f"Database error: {e}")
            return False
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    def open_admin_panel(self, username):
        self.admin_window = AdminPanel(username)
        self.admin_window.show()
        self.close()

    def open_user_panel(self, username):
        self.user_window = UserPanel(username)
        self.user_window.show()
        self.close()

class CreatePasswordWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("Create Password")
        self.setGeometry(300, 300, 400, 200)
        layout = QVBoxLayout()

        self.label = QLabel("New Password:")
        layout.addWidget(self.label)
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_password)

        self.label2 = QLabel("Confirm New Password:")
        layout.addWidget(self.label2)
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password)

        self.create_btn = QPushButton("Create Password")
        self.create_btn.clicked.connect(self.handle_create_password)
        layout.addWidget(self.create_btn)

        self.setLayout(layout)

    def handle_create_password(self):
        new_password = self.new_password.text()
        confirm_password = self.confirm_password.text()

        if new_password != confirm_password:
            show_error("Passwords do not match!")
            return

        conn = connect_db()
        cur = conn.cursor()
        hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        cur.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, self.username))
        conn.commit()
        cur.close()
        conn.close()
        show_info("Password created successfully!")
        self.close()

class AdminPanel(QWidget):
    def __init__(self, current_user):
        super().__init__()
        self.current_user = current_user
        self.setWindowTitle(f"Admin Panel - {self.current_user}")
        self.setGeometry(200, 200, 800, 600)
        layout = QHBoxLayout()

        # Список пользователей слева
        self.user_list = QListWidget()
        self.user_list.itemClicked.connect(self.show_user_details)
        layout.addWidget(self.user_list)

        # Панель действий справа
        self.action_panel = QGroupBox("Actions")
        action_layout = QVBoxLayout()

        self.create_user_btn = QPushButton("Create User")
        self.create_user_btn.clicked.connect(self.create_user)
        action_layout.addWidget(self.create_user_btn)

        self.block_user_btn = QPushButton("Block User")
        self.block_user_btn.clicked.connect(self.block_user)
        action_layout.addWidget(self.block_user_btn)

        self.unblock_user_btn = QPushButton("Unblock User")
        self.unblock_user_btn.clicked.connect(self.unblock_user)
        action_layout.addWidget(self.unblock_user_btn)

        self.reset_password_btn = QPushButton("Reset Password")
        self.reset_password_btn.clicked.connect(self.reset_password)
        action_layout.addWidget(self.reset_password_btn)

        self.set_admin_btn = QPushButton("Set Admin")
        self.set_admin_btn.clicked.connect(self.set_admin)
        action_layout.addWidget(self.set_admin_btn)

        self.remove_admin_btn = QPushButton("Remove Admin")
        self.remove_admin_btn.clicked.connect(self.remove_admin)
        action_layout.addWidget(self.remove_admin_btn)

        self.set_attempts_btn = QPushButton("Set Max Attempts")
        self.set_attempts_btn.clicked.connect(self.set_max_attempts)
        action_layout.addWidget(self.set_attempts_btn)

        self.require_special_chars = QCheckBox("Require Special Characters")
        action_layout.addWidget(self.require_special_chars)

        self.require_uppercase = QCheckBox("Require Uppercase Letters")
        action_layout.addWidget(self.require_uppercase)

        self.require_lowercase = QCheckBox("Require Lowercase Letters")
        action_layout.addWidget(self.require_lowercase)

        self.require_digits = QCheckBox("Require Digits")
        action_layout.addWidget(self.require_digits)

        self.save_restrictions_btn = QPushButton("Save Password Restrictions")
        self.save_restrictions_btn.clicked.connect(self.save_password_restrictions)
        action_layout.addWidget(self.save_restrictions_btn)

        self.delete_user_btn = QPushButton("Delete User")
        self.delete_user_btn.clicked.connect(self.delete_user)
        action_layout.addWidget(self.delete_user_btn)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        action_layout.addWidget(self.logout_btn)

        self.action_panel.setLayout(action_layout)
        layout.addWidget(self.action_panel)

        self.setLayout(layout)
        self.refresh_users()

    def refresh_users(self):
        self.user_list.clear()
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT username, is_blocked, is_admin FROM users")
        users = cur.fetchall()
        for user in users:
            item = QListWidgetItem(user[0])
            if user[1]:  # Если пользователь заблокирован
                item.setIcon(QIcon.fromTheme("dialog-error"))  # Красный крестик
            elif user[2]:  # Если пользователь админ
                item.setIcon(QIcon.fromTheme("emblem-default"))  # Зеленая галочка
            self.user_list.addItem(item)
        cur.close()
        conn.close()

    def show_user_details(self, item):
        username = item.text()
        self.user_details_window = UserDetailsWindow(username)
        self.user_details_window.show()

    def create_user(self):
        username, ok = QInputDialog.getText(self, "Create User", "Enter username:")
        if ok and username:
            if not validate_username(username):
                show_error("Invalid username!")
                return
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                show_error(f"User '{username}' already exists!")
                return
            cur.execute("INSERT INTO users (username, max_attempts) VALUES (%s, %s)",
                        (username, 3))  # По умолчанию max_attempts = 3
            conn.commit()
            cur.close()
            conn.close()
            self.refresh_users()

    def block_user(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            if username == "ADMIN":
                show_error("Cannot block the main admin!")
                return
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("SELECT is_admin FROM users WHERE username = %s", (username,))
            is_admin = cur.fetchone()[0]
            if is_admin:
                show_error("Cannot block an admin user!")
                return
            cur.execute("UPDATE users SET is_blocked = TRUE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            self.refresh_users()

    def unblock_user(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("UPDATE users SET is_blocked = FALSE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            self.refresh_users()

    def reset_password(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("UPDATE users SET password = NULL WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            show_info(f"Password for {username} has been reset.")

    def set_admin(self):
        if self.current_user != "ADMIN":
            show_error("Only the main admin can grant admin rights!")
            return
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("UPDATE users SET is_admin = TRUE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            self.refresh_users()

    def remove_admin(self):
        if self.current_user != "ADMIN":
            show_error("Only the main admin can remove admin rights!")
            return
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            if username == "ADMIN":
                show_error("Cannot remove admin rights from the main admin!")
                return
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("UPDATE users SET is_admin = FALSE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            self.refresh_users()

    def set_max_attempts(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            if username == "ADMIN":
                show_error("Cannot change max attempts for the main admin!")
                return
            attempts, ok = QInputDialog.getInt(self, "Set Max Attempts", "Enter maximum number of attempts:")
            if ok:
                conn = connect_db()
                cur = conn.cursor()
                cur.execute("UPDATE users SET max_attempts = %s WHERE username = %s", (attempts, username))
                conn.commit()
                cur.close()
                conn.close()
                self.refresh_users()

    def save_password_restrictions(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            special_chars = self.require_special_chars.isChecked()
            uppercase = self.require_uppercase.isChecked()
            lowercase = self.require_lowercase.isChecked()
            digits = self.require_digits.isChecked()

            conn = connect_db()
            cur = conn.cursor()
            cur.execute("""
                UPDATE users 
                SET require_special_chars = %s, 
                    require_uppercase = %s, 
                    require_lowercase = %s, 
                    require_digits = %s 
                WHERE username = %s
            """, (special_chars, uppercase, lowercase, digits, username))
            conn.commit()
            cur.close()
            conn.close()
            show_info("Password restrictions updated successfully!")

    def delete_user(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            if username == "ADMIN":
                show_error("Cannot delete the main admin!")
                return
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            self.refresh_users()

    def logout(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

    def closeEvent(self, event):
        if hasattr(self, 'login_window'):
            self.login_window.close_all_db_connections()
        event.accept()

class UserPanel(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle(f"User Panel - {self.username}")
        self.setGeometry(200, 200, 600, 400)
        layout = QHBoxLayout()

        # Информация о пользователе слева
        self.user_info = QGroupBox("User Info")
        info_layout = QFormLayout()

        self.email_label = QLabel("Email:")
        self.email = QLineEdit()
        info_layout.addRow(self.email_label, self.email)

        self.cn_label = QLabel("CN:")
        self.cn = QLineEdit()
        info_layout.addRow(self.cn_label, self.cn)

        self.description_label = QLabel("Description:")
        self.description = QLineEdit()
        info_layout.addRow(self.description_label, self.description)

        self.phonenumber_label = QLabel("Phone Number:")
        self.phonenumber = QLineEdit()
        info_layout.addRow(self.phonenumber_label, self.phonenumber)

        self.user_info.setLayout(info_layout)
        layout.addWidget(self.user_info)

        # Панель действий справа
        self.action_panel = QGroupBox("Actions")
        action_layout = QVBoxLayout()

        self.change_password_btn = QPushButton("Change Password")
        self.change_password_btn.clicked.connect(self.change_password)
        action_layout.addWidget(self.change_password_btn)

        self.save_changes_btn = QPushButton("Save Changes")
        self.save_changes_btn.clicked.connect(self.save_changes)
        action_layout.addWidget(self.save_changes_btn)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        action_layout.addWidget(self.logout_btn)

        self.action_panel.setLayout(action_layout)
        layout.addWidget(self.action_panel)

        self.setLayout(layout)
        self.load_user_details()

    def load_user_details(self):
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT email, cn, description, phonenumber FROM users WHERE username = %s", (self.username,))
        user = cur.fetchone()
        if user:
            self.email.setText(user[0] or "")
            self.cn.setText(user[1] or "")
            self.description.setText(user[2] or "")
            self.phonenumber.setText(user[3] or "")
        cur.close()
        conn.close()

    def save_changes(self):
        email = self.email.text()
        cn = self.cn.text()
        description = self.description.text()
        phonenumber = self.phonenumber.text()

        conn = connect_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET email = %s, cn = %s, description = %s, phonenumber = %s WHERE username = %s",
                    (email, cn, description, phonenumber, self.username))
        conn.commit()
        cur.close()
        conn.close()
        show_info("User details updated successfully!")

    def change_password(self):
        self.change_password_window = ChangePasswordWindow(self.username)
        self.change_password_window.show()

    def logout(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

    def closeEvent(self, event):
        if hasattr(self, 'login_window'):
            self.login_window.close_all_db_connections()
        event.accept()

class ChangePasswordWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("Change Password")
        self.setGeometry(300, 300, 400, 250)
        layout = QVBoxLayout()

        self.label = QLabel("Old Password:")
        layout.addWidget(self.label)
        self.old_password = QLineEdit()
        self.old_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.old_password)

        self.label2 = QLabel("New Password:")
        layout.addWidget(self.label2)
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_password)

        self.label3 = QLabel("Confirm New Password:")
        layout.addWidget(self.label3)
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_password)

        self.change_btn = QPushButton("Change Password")
        self.change_btn.clicked.connect(self.handle_change_password)
        layout.addWidget(self.change_btn)

        self.setLayout(layout)

    def handle_change_password(self):
        old_password = self.old_password.text()
        new_password = self.new_password.text()
        confirm_password = self.confirm_password.text()

        if new_password != confirm_password:
            show_error("New passwords do not match!")
            return

        is_valid, message = validate_password(new_password, self.username)
        if not is_valid:
            show_error(message)
            return

        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username = %s", (self.username,))
        user = cur.fetchone()

        if user and bcrypt.checkpw(old_password.encode(), user[0].encode()):
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            cur.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, self.username))
            conn.commit()
            cur.close()
            conn.close()
            show_info("Password changed successfully!")
            self.close()
        else:
            show_error("Old password is incorrect!")
            cur.close()
            conn.close()

class UserDetailsWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("User Details")
        self.setGeometry(300, 300, 400, 300)
        layout = QVBoxLayout()

        self.label = QLabel(f"Details for {username}")
        layout.addWidget(self.label)

        self.email_label = QLabel("Email:")
        layout.addWidget(self.email_label)
        self.email = QLineEdit()
        layout.addWidget(self.email)

        self.cn_label = QLabel("CN:")
        layout.addWidget(self.cn_label)
        self.cn = QLineEdit()
        layout.addWidget(self.cn)

        self.description_label = QLabel("Description:")
        layout.addWidget(self.description_label)
        self.description = QLineEdit()
        layout.addWidget(self.description)

        self.phonenumber_label = QLabel("Phone Number:")
        layout.addWidget(self.phonenumber_label)
        self.phonenumber = QLineEdit()
        layout.addWidget(self.phonenumber)

        self.save_btn = QPushButton("Save Changes")
        self.save_btn.clicked.connect(self.save_changes)
        layout.addWidget(self.save_btn)

        self.load_user_details()

        self.setLayout(layout)

    def load_user_details(self):
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT email, cn, description, phonenumber FROM users WHERE username = %s", (self.username,))
        user = cur.fetchone()
        if user:
            self.email.setText(user[0] or "")
            self.cn.setText(user[1] or "")
            self.description.setText(user[2] or "")
            self.phonenumber.setText(user[3] or "")
        cur.close()
        conn.close()

    def save_changes(self):
        email = self.email.text()
        cn = self.cn.text()
        description = self.description.text()
        phonenumber = self.phonenumber.text()

        conn = connect_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET email = %s, cn = %s, description = %s, phonenumber = %s WHERE username = %s",
                    (email, cn, description, phonenumber, self.username))
        conn.commit()
        cur.close()
        conn.close()
        show_info("User details updated successfully!")
        self.close()


if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    window = LoginWindow()
    app.active_window = window  # Сохраняем ссылку на главное окно
    window.show()
    ret = app.exec()

    # Гарантируем закрытие всех соединений при выходе
    window.close_all_db_connections()
    sys.exit(ret)