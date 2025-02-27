import os
import sys
import bcrypt
import psycopg2
import logging
import re
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QListWidget, QGroupBox, QFormLayout, QInputDialog, QListWidgetItem, QCheckBox
)
from PySide6.QtGui import QIcon

# Настройка логирования
LOG_FILE = os.path.expanduser("~/InfSec/var/log/lab3.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)  # Создаем директорию, если её нет
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Конфигурация БД
DB_CONFIG = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def connect_db():
    return psycopg2.connect(**DB_CONFIG)

def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return False
    return True

def validate_password(password, username):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT require_special_chars, require_uppercase, require_lowercase, require_digits 
        FROM users WHERE username = %s
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

def log_event(event):
    logging.info(event)

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
    conn = connect_db()
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

    conn.commit()
    cur.close()
    conn.close()

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setGeometry(300, 300, 300, 150)
        layout = QVBoxLayout()

        self.label = QLabel("Username:")
        layout.addWidget(self.label)
        self.username_input = QLineEdit()
        layout.addWidget(self.username_input)

        self.label2 = QLabel("Password:")
        layout.addWidget(self.label2)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        self.setLayout(layout)

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not validate_username(username):
            show_error("Invalid username!")
            return

        conn = connect_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT password, is_blocked, max_attempts, require_special_chars, require_uppercase, require_lowercase, require_digits 
            FROM users WHERE username = %s
        """, (username,))
        user = cur.fetchone()

        if user:
            hashed_pw, is_blocked, max_attempts, require_special_chars, require_uppercase, require_lowercase, require_digits = user

            if is_blocked:
                show_error("User is blocked!")
                return

            # Если пароль не задан (NULL), перенаправляем на создание пароля
            if hashed_pw is None:
                self.create_password_window = CreatePasswordWindow(username)
                self.create_password_window.show()
                self.close()
                return

            # Проверяем пароль
            if bcrypt.checkpw(password.encode(), hashed_pw.encode()):
                if username == "ADMIN":
                    self.open_admin_panel(username)
                else:
                    self.open_user_panel(username)
            else:
                failed_attempts = max_attempts - 1
                if failed_attempts <= 0:
                    cur.execute("UPDATE users SET is_blocked = TRUE WHERE username = %s", (username,))
                    show_error("Too many failed attempts, user blocked!")
                    logging.warning(f"User {username} blocked after too many failed login attempts")
                else:
                    show_error(f"Invalid credentials! Attempts left: {failed_attempts}")
                    logging.warning(f"Failed login attempt for user {username}")
                cur.execute("UPDATE users SET max_attempts = %s WHERE username = %s", (failed_attempts, username))
                conn.commit()
        else:
            show_error("Invalid credentials!")
            logging.warning(f"Non-existent user {username} attempted login")

        cur.close()
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

        log_event(f"User {self.username} created a password")
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
            log_event(f"User {username} created by {self.current_user}")
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
            log_event(f"User {username} blocked by {self.current_user}")
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
            log_event(f"User {username} unblocked by {self.current_user}")
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
            log_event(f"Password reset for user {username} by {self.current_user}")
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
            log_event(f"User {username} granted admin rights by {self.current_user}")
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
            log_event(f"Admin rights removed for user {username} by {self.current_user}")
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
                log_event(f"Max attempts set to {attempts} for user {username} by {self.current_user}")
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
            log_event(f"Password restrictions updated for user {username} by {self.current_user}")
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
            log_event(f"User {username} deleted by {self.current_user}")
            self.refresh_users()

    def logout(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

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

        log_event(f"User {self.username} details updated")
        show_info("User details updated successfully!")

    def change_password(self):
        self.change_password_window = ChangePasswordWindow(self.username)
        self.change_password_window.show()

    def logout(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

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

            log_event(f"User {self.username} changed their password")
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

        log_event(f"User {self.username} details updated by ADMIN")
        show_info("User details updated successfully!")
        self.close()

if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())