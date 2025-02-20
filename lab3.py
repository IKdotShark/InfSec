import os
import sys
import bcrypt
import psycopg2
import logging
import uuid
import re
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QListWidget, QGroupBox, QFormLayout, QInputDialog, QListWidgetItem
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

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True

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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 32),
            guid UUID UNIQUE NOT NULL,
            password TEXT,
            email TEXT,
            cn TEXT,
            description TEXT,
            phonenumber TEXT,
            is_admin BOOLEAN DEFAULT FALSE NOT NULL,
            is_blocked BOOLEAN DEFAULT FALSE NOT NULL,
            failed_attempts INTEGER DEFAULT 0 NOT NULL
        )
    """)
    conn.commit()
    cur.execute("SELECT * FROM users WHERE username='ADMIN'")
    if not cur.fetchone():
        hashed_pw = bcrypt.hashpw(b"ADMIN", bcrypt.gensalt()).decode()
        cur.execute("INSERT INTO users (username, guid, password, is_admin) VALUES (%s, %s, %s, TRUE)",
                    ('ADMIN', str(uuid.uuid4()), hashed_pw))
        conn.commit()
    cur.close()
    conn.close()

# Класс окна авторизации
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setGeometry(100, 100, 400, 250)
        layout = QVBoxLayout()

        self.label = QLabel("Username:")
        layout.addWidget(self.label)
        self.username = QLineEdit()
        layout.addWidget(self.username)

        self.label2 = QLabel("Password:")
        layout.addWidget(self.label2)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        self.setLayout(layout)

    def handle_login(self):
        username = self.username.text()
        password = self.password.text()
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT password, is_admin, is_blocked, failed_attempts FROM users WHERE username = %s",
                    (username,))
        user = cur.fetchone()

        if user:
            if user[2]:  # Если пользователь заблокирован
                show_error("User is blocked!")
                logging.warning(f"Blocked user {username} attempted login")
            elif user[0] is None:  # Если пароль NULL, открываем окно создания пароля
                self.open_create_password_window(username)
            elif bcrypt.checkpw(password.encode(), user[0].encode()):
                cur.execute("UPDATE users SET failed_attempts = 0 WHERE username = %s", (username,))
                conn.commit()
                if user[1]:
                    self.open_admin_panel()
                else:
                    self.open_user_panel(username)
                logging.info(f"User {username} logged in successfully")
            else:
                failed_attempts = user[3] + 1
                if failed_attempts >= 3:
                    cur.execute("UPDATE users SET is_blocked = TRUE WHERE username = %s", (username,))
                    show_error("Too many failed attempts, user blocked!")
                    logging.warning(f"User {username} blocked after too many failed login attempts")
                else:
                    cur.execute("UPDATE users SET failed_attempts = %s WHERE username = %s",
                                (failed_attempts, username))
                    show_error("Invalid credentials!")
                    logging.warning(f"Failed login attempt for user {username}")
                conn.commit()
        else:
            show_error("Invalid credentials!")
            logging.warning(f"Non-existent user {username} attempted login")

        cur.close()
        conn.close()

    def open_admin_panel(self):
        self.admin_window = AdminPanel()
        self.admin_window.show()
        self.close()

    def open_user_panel(self, username):
        self.user_window = UserPanel(username)
        self.user_window.show()
        self.close()

    def open_create_password_window(self, username):
        self.create_password_window = CreatePasswordWindow(username)
        self.create_password_window.show()

# Окно создания пароля
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

        if not validate_password(new_password):
            show_error("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit.")
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

# Панель администратора
class AdminPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Admin Panel")
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
        cur.execute("SELECT username, is_blocked FROM users")
        users = cur.fetchall()
        for user in users:
            item = QListWidgetItem(user[0])
            if user[1]:  # Если пользователь заблокирован
                item.setIcon(QIcon.fromTheme("dialog-error"))  # Красный крестик
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
            cur.execute("INSERT INTO users (username, guid) VALUES (%s, %s)", (username, str(uuid.uuid4())))
            conn.commit()
            cur.close()
            conn.close()
            log_event(f"User {username} created by ADMIN")
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
            cur.execute("UPDATE users SET is_blocked = TRUE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            log_event(f"User {username} blocked by ADMIN")
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
            log_event(f"User {username} unblocked by ADMIN")
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
            log_event(f"Password reset for user {username} by ADMIN")
            show_info(f"Password for {username} has been reset.")

    def set_admin(self):
        user = self.user_list.currentItem()
        if user:
            username = user.text()
            conn = connect_db()
            cur = conn.cursor()
            cur.execute("UPDATE users SET is_admin = TRUE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            log_event(f"User {username} granted admin rights by ADMIN")
            self.refresh_users()

    def remove_admin(self):
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
            log_event(f"Admin rights removed for user {username} by ADMIN")
            self.refresh_users()

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
            log_event(f"User {username} deleted by ADMIN")
            self.refresh_users()

    def logout(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

# Панель пользователя
class UserPanel(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("User Panel")
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

# Окно смены пароля
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

        if not validate_password(new_password):
            show_error("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit.")
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

# Окно деталей пользователя
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