import sys
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFormLayout, QComboBox
)
from sympy import Integer

class PasswordCheckerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Checker")
        self.setGeometry(300, 300, 400, 300)
        layout = QVBoxLayout()

        # Форма для ввода данных
        form_layout = QFormLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Password:", self.password_input)

        self.speed_input = QLineEdit()
        form_layout.addRow("Speed (attempts per second):", self.speed_input)

        self.attempts_input = QLineEdit()
        form_layout.addRow("Failed attempts before pause:", self.attempts_input)

        self.pause_input = QLineEdit()
        form_layout.addRow("Pause time (seconds):", self.pause_input)

        layout.addLayout(form_layout)

        # Кнопка для запуска проверки
        self.check_btn = QPushButton("Check Password")
        self.check_btn.clicked.connect(self.check_password)
        layout.addWidget(self.check_btn)

        # Поля для вывода результатов
        self.alphabet_label = QLabel("Alphabet Size: ")
        layout.addWidget(self.alphabet_label)

        self.combinations_label = QLabel("Total Possible Passwords: ")
        layout.addWidget(self.combinations_label)

        self.time_label = QLabel("Estimated Time to Crack: ")
        layout.addWidget(self.time_label)

        self.setLayout(layout)

    def get_alphabet_size(self, password):
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

    def format_time(self, total_seconds):
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

        return f"{years} years, {months} months, {days} days, {hours} hours, {minutes} minutes, {seconds} seconds"

    def check_password(self):
        """
        Основная логика программы: расчет времени подбора пароля.
        """
        password = self.password_input.text()
        speed = Integer(self.speed_input.text())
        attempts_before_pause = Integer(self.attempts_input.text())
        pause_time = Integer(self.pause_input.text())

        alphabet_size = self.get_alphabet_size(password)
        total_combinations = Integer(alphabet_size) ** len(password)
        base_time_seconds = total_combinations // speed

        pause_count = (total_combinations - 1) // attempts_before_pause
        total_time_seconds = base_time_seconds + pause_count * pause_time

        # Вывод результатов в GUI
        self.alphabet_label.setText(f"Alphabet Size: {alphabet_size}")
        self.combinations_label.setText(f"Total Possible Passwords: {total_combinations}")
        self.time_label.setText(f"Estimated Time to Crack: {self.format_time(total_time_seconds)}")

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Tool")
        self.setGeometry(300, 300, 400, 200)
        layout = QVBoxLayout()

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Password Checker")
        self.mode_combo.addItem("Password Cracker")
        layout.addWidget(self.mode_combo)

        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start_mode)
        layout.addWidget(self.start_btn)

        self.setLayout(layout)

    def start_mode(self):
        mode = self.mode_combo.currentText()
        if mode == "Password Checker":
            self.password_checker = PasswordCheckerWindow()
            self.password_checker.show()
        else:
            # Здесь можно добавить логику для режима Password Cracker
            pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())