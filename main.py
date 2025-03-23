import sys
import pyperclip
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QTextEdit, QPushButton, QTabWidget, QComboBox, QCheckBox, QGroupBox,
                             QFormLayout, QMessageBox)

from aes_encryption import AESEncryptionDecryption
from password_generator import PasswordGenerator

class ToolHelperApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Tool Helper")
        self.setGeometry(100, 100, 800, 600)
        self.setFixedSize(800, 600)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        # Create the layout and the tab widget
        layout = QVBoxLayout(self.central_widget)
        self.notebook = QTabWidget()
        layout.addWidget(self.notebook)
        
        # Creating the tabs
        self.create_encryption_tab()
        self.create_aes_tab()
        self.create_rsa_tab()
        self.create_password_tab()

    def create_encryption_tab(self):
        tab = QWidget()
        self.notebook.addTab(tab, "Encryption/Decryption")

        layout = QVBoxLayout(tab)

        # Key Entry
        layout.addWidget(QLabel("Secret Key"))
        self.key_entry = QLineEdit()
        layout.addWidget(self.key_entry)

        # Data Entry
        layout.addWidget(QLabel("Data"))
        self.data_text = QTextEdit()
        layout.addWidget(self.data_text)

        # Encrypt and Decrypt Buttons
        button_layout = QHBoxLayout()
        encrypt_button = QPushButton("Encrypt")
        decrypt_button = QPushButton("Decrypt")
        button_layout.addWidget(encrypt_button)
        button_layout.addWidget(decrypt_button)
        layout.addLayout(button_layout)

        # Result Text
        layout.addWidget(QLabel("Result"))
        self.result_text = QTextEdit()
        layout.addWidget(self.result_text)

        # Copy and Clear Buttons
        button_layout2 = QHBoxLayout()
        copy_button = QPushButton("Copy")
        clear_button = QPushButton("Clear")
        button_layout2.addWidget(copy_button)
        button_layout2.addWidget(clear_button)
        layout.addLayout(button_layout2)

        # Connect buttons to their respective actions
        encrypt_button.clicked.connect(self.encrypt_data)
        decrypt_button.clicked.connect(self.decrypt_data)  # Connect to decrypt_data
        copy_button.clicked.connect(self.copy_result)
        clear_button.clicked.connect(self.clear_encryption_fields)

    def create_aes_tab(self):
        tab = QWidget()
        self.notebook.addTab(tab, "Generate AES Key")
        
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Key Size (Bit):"))
        self.aes_size = QComboBox()
        self.aes_size.addItems(["128", "192", "256"])
        layout.addWidget(self.aes_size)
        
        generate_button = QPushButton("Generate")
        generate_button.clicked.connect(self.generate_aes_key)
        layout.addWidget(generate_button)
        
        layout.addWidget(QLabel("Passphrase (Optional):"))
        self.aes_passphrase_entry = QLineEdit()
        layout.addWidget(self.aes_passphrase_entry)
        
        layout.addWidget(QLabel("Result"))
        self.aes_result = QTextEdit()
        layout.addWidget(self.aes_result)
        
        # Copy and Clear Buttons
        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy")
        clear_button = QPushButton("Clear")
        copy_button.clicked.connect(self.copy_aes_key)
        clear_button.clicked.connect(self.clear_aes_fields)
        button_layout.addWidget(copy_button)
        button_layout.addWidget(clear_button)
        layout.addLayout(button_layout)

    def create_rsa_tab(self):
        tab = QWidget()
        self.notebook.addTab(tab, "Generate Public/Private Keys")
        
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Key Size (Bit):"))
        self.rsa_size = QComboBox()
        self.rsa_size.addItems(["512", "1024", "2048", "3072", "4096"])
        layout.addWidget(self.rsa_size)
        
        layout.addWidget(QLabel("Output Format:"))
        self.format_var = QComboBox()
        self.format_var.addItems(["PKCS-1", "PKCS-8", "Open SSH", "Putty"])
        layout.addWidget(self.format_var)
        
        layout.addWidget(QLabel("SSH format (Optional):"))
        self.ssh_entry = QLineEdit()
        layout.addWidget(self.ssh_entry)
        
        layout.addWidget(QLabel("Passphrase (Optional):"))
        self.rsa_passphrase_entry = QLineEdit()
        layout.addWidget(self.rsa_passphrase_entry)
        
        generate_button = QPushButton("Generate")
        generate_button.clicked.connect(self.generate_rsa_keys)
        layout.addWidget(generate_button)
        
        # Result Section
        layout.addWidget(QLabel("Result"))
        
        result_layout = QHBoxLayout()
        
        # Public Key
        self.rsa_pub_text = QTextEdit()
        result_layout.addWidget(QLabel("Public Key:"))
        result_layout.addWidget(self.rsa_pub_text)
        
        # Private Key
        self.rsa_priv_text = QTextEdit()
        result_layout.addWidget(QLabel("Private Key:"))
        result_layout.addWidget(self.rsa_priv_text)
        
        layout.addLayout(result_layout)
        
        # Copy and Clear Buttons
        button_layout = QHBoxLayout()
        copy_pub_button = QPushButton("Copy Public")
        copy_priv_button = QPushButton("Copy Private")
        clear_button = QPushButton("Clear")
        copy_pub_button.clicked.connect(self.copy_public_key)
        copy_priv_button.clicked.connect(self.copy_private_key)
        clear_button.clicked.connect(self.clear_rsa_fields)
        button_layout.addWidget(copy_pub_button)
        button_layout.addWidget(copy_priv_button)
        button_layout.addWidget(clear_button)
        layout.addLayout(button_layout)

    def create_password_tab(self):
        tab = QWidget()
        self.notebook.addTab(tab, "Generate Password")
        
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Password Length:"))
        self.password_length = QComboBox()
        self.password_length.addItems([str(i) for i in [8, 12, 16, 20, 24]])
        layout.addWidget(self.password_length)
        
        # Password Options
        options = ["Include Number", "Include Lowercase", "Include Uppercase", "Include Symbols", "No Duplicate"]
        self.options_vars = {}
        for option in options:
            checkbox = QCheckBox(option)
            self.options_vars[option] = checkbox
            layout.addWidget(checkbox)
        
        generate_button = QPushButton("Generate")
        generate_button.clicked.connect(self.generate_password)
        layout.addWidget(generate_button)
        
        layout.addWidget(QLabel("Result"))
        self.password_result = QTextEdit()
        layout.addWidget(self.password_result)
        
        # Copy and Clear Buttons
        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy")
        clear_button = QPushButton("Clear")
        copy_button.clicked.connect(self.copy_password)
        clear_button.clicked.connect(self.clear_password_fields)
        button_layout.addWidget(copy_button)
        button_layout.addWidget(clear_button)
        layout.addLayout(button_layout)

    # Helper Methods
    def encrypt_data(self):
        secret = self.key_entry.text().strip()
        data = self.data_text.toPlainText().strip()
        
        if secret and data:
            aes = AESEncryptionDecryption()
            encrypted_data = aes.encrypt_aes(data, secret)
            if encrypted_data:
                self.result_text.setPlainText(encrypted_data)
            else:
                self.show_message("Error during encryption")

    def decrypt_data(self):  # Add the decrypt_data method here
        secret = self.key_entry.text().strip()
        encrypted_data = self.result_text.toPlainText().strip()
        
        if secret and encrypted_data:
            aes = AESEncryptionDecryption()
            decrypted_data = aes.decrypt_aes(encrypted_data, secret)
            if decrypted_data:
                self.result_text.setPlainText(decrypted_data)
            else:
                self.show_message("Error during decryption")

    def copy_result(self):
        result = self.result_text.toPlainText().strip()
        if result:
            pyperclip.copy(result)
            self.show_message("Result copied to clipboard!")

    def clear_encryption_fields(self):
        """Clear all fields related to encryption."""
        self.key_entry.clear()
        self.data_text.clear()
        self.result_text.clear()

    def generate_aes_key(self):
        key_size = self.aes_size.currentText()
        passphrase = self.aes_passphrase_entry.text()
        result = f"AES Key (Size: {key_size}):\n{passphrase}"
        self.aes_result.setPlainText(result)

    def copy_aes_key(self):
        aes_key = self.aes_result.toPlainText().strip()
        if aes_key:
            pyperclip.copy(aes_key)
            self.show_message("AES Key copied to clipboard!")

    def clear_aes_fields(self):
        self.aes_size.setCurrentIndex(0)
        self.aes_passphrase_entry.clear()
        self.aes_result.clear()

    def generate_rsa_keys(self):
        key_size = self.rsa_size.currentText()
        key_format = self.format_var.currentText()
        passphrase = self.rsa_passphrase_entry.text()
        result_pub = f"Public Key (Size: {key_size}, Format: {key_format}):\n{passphrase}"
        result_priv = f"Private Key (Size: {key_size}, Format: {key_format}):\n{passphrase}"
        self.rsa_pub_text.setPlainText(result_pub)
        self.rsa_priv_text.setPlainText(result_priv)

    def copy_public_key(self):
        pub_key = self.rsa_pub_text.toPlainText().strip()
        if pub_key:
            pyperclip.copy(pub_key)
            self.show_message("Public Key copied to clipboard!")

    def copy_private_key(self):
        priv_key = self.rsa_priv_text.toPlainText().strip()
        if priv_key:
            pyperclip.copy(priv_key)
            self.show_message("Private Key copied to clipboard!")

    def clear_rsa_fields(self):
        self.rsa_size.setCurrentIndex(0)
        self.format_var.setCurrentIndex(0)
        self.ssh_entry.clear()
        self.rsa_passphrase_entry.clear()
        self.rsa_pub_text.clear()
        self.rsa_priv_text.clear()

    def generate_password(self):
        length = int(self.password_length.currentText())
        include_numbers = self.options_vars["Include Number"].isChecked()
        include_lowercase = self.options_vars["Include Lowercase"].isChecked()
        include_uppercase = self.options_vars["Include Uppercase"].isChecked()
        include_symbols = self.options_vars["Include Symbols"].isChecked()
        no_duplicates = self.options_vars["No Duplicate"].isChecked()
        
        # Create PasswordGenerator instance
        password_gen = PasswordGenerator(length, include_numbers, include_lowercase, include_uppercase, include_symbols, no_duplicates)
        password = password_gen.generate()
        
        self.password_result.setPlainText(password)

    def copy_password(self):
        password = self.password_result.toPlainText().strip()
        if password:
            pyperclip.copy(password)
            self.show_message("Password copied to clipboard!")

    def clear_password_fields(self):
        self.password_length.setCurrentIndex(0)
        for option in self.options_vars.values():
            option.setChecked(False)
        self.password_result.clear()

    def show_message(self, message):
        QMessageBox.information(self, "Information", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ToolHelperApp()
    window.show()
    sys.exit(app.exec_())
