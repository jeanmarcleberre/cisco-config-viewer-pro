#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cisco Config Viewer PRO v2.0 - Version autonome
Support: Catalyst 9200 - IOS XE Amsterdam 17.3.x
Fonctionnalités: Lecture config, SSH, Diff, Validation, Export PDF
"""

import sys
import os
import re
import json
import yaml
from datetime import datetime
from pathlib import Path
from difflib import HtmlDiff
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QPushButton, QFileDialog, QLineEdit,
    QLabel, QSplitter, QMessageBox, QInputDialog, QFormLayout, QDialog,
    QDialogButtonBox, QProgressBar, QStatusBar, QMenuBar, QToolBar,
    QComboBox, QCheckBox, QGroupBox, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QAction, QKeySequence
from PyQt6.Qsci import QsciScintilla

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    NetmikoTimeoutException = Exception
    NetmikoAuthenticationException = Exception
    ConnectHandler = None

# Chemins
BASE_DIR = Path(__file__).parent
COMMANDS_DB = BASE_DIR / "commands_db" / "ios_xe_17.3_commands.json"
TEMPLATES_DIR = BASE_DIR / "templates"
SAVE_DIR = Path.home() / ".cisco_config_viewer"
SAVE_DIR.mkdir(exist_ok=True)

# Chargement base de commandes
with open(COMMANDS_DB, 'r', encoding='utf-8') as f:
    VALID_COMMANDS = json.load(f)

# Lexer Cisco simple (sans QsciLexerCustom pour simplicité)
class CiscoLexer:
    def highlight(self, editor):
        text = editor.text()
        cursor = editor.textCursor()
        # Simple coloration (ex: interface en bleu)
        for match in re.finditer(r'(interface|router|vlan|ip access-list)', text, re.IGNORECASE):
            cursor.setPosition(match.start())
            cursor.setPosition(match.end())
            cursor.setCharFormat(QTextCharFormat().setForeground(QColor("blue")))
        editor.setTextCursor(cursor)

# Thread Validation
class ValidationThread(QThread):
    finished = pyqtSignal(list, dict)

    def __init__(self, lines):
        super().__init__()
        self.lines = lines

    def run(self):
        issues = []
        stats = {"valid": 0, "deprecated": 0, "errors": 0}

        for i, line in enumerate(self.lines):
            cmd = line.strip()
            if not cmd or cmd.startswith('!'):
                continue

            found = False
            deprecated = False
            for pattern, data in VALID_COMMANDS.items():
                if re.match(f"^{pattern}", cmd, re.IGNORECASE):
                    found = True
                    if not data.get("valid", True):
                        issues.append({"line": i+1, "command": cmd, "type": "error", "message": f"Obsolète: {data.get('replacement', 'N/A')}"})
                        stats["errors"] += 1
                        deprecated = True
                    elif data.get("deprecated_in"):
                        issues.append({"line": i+1, "command": cmd, "type": "warning", "message": f"Dépréciée depuis {data['deprecated_in']}"})
                        stats["deprecated"] += 1
                        deprecated = True
                    break

            if not found and not deprecated:
                issues.append({"line": i+1, "command": cmd, "type": "error", "message": "Commande non reconnue dans IOS XE 17.3.x"})
                stats["errors"] += 1
            elif not deprecated:
                stats["valid"] += 1

        self.finished.emit(issues, stats)

# Thread SSH
class SSHThread(QThread):
    finished = pyqtSignal(str, str)
    error = pyqtSignal(str)

    def __init__(self, device):
        super().__init__()
        self.device = device

    def run(self):
        try:
            conn = ConnectHandler(**self.device)
            config = conn.send_command("show startup-config")
            hostname = conn.find_prompt()[:-1]
            conn.disconnect()
            self.finished.emit(config, hostname)
        except Exception as e:
            self.error.emit(str(e))

# Fenêtre principale
class CiscoConfigViewerPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.tabs = {}
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Cisco Config Viewer PRO v2.0 - IOS XE 17.3.x")
        self.setGeometry(100, 100, 1400, 900)

        # Menu
        menubar = self.menuBar()
        file_menu = menubar.addMenu("Fichier")
        open_act = QAction("Ouvrir", self)
        open_act.setShortcut("Ctrl+O")
        open_act.triggered.connect(self.open_file)
        file_menu.addAction(open_act)

        ssh_menu = menubar.addMenu("SSH")
        ssh_act = QAction("Télécharger config", self)
        ssh_act.setShortcut("Ctrl+T")
        ssh_act.triggered.connect(self.ssh_dialog)
        ssh_menu.addAction(ssh_act)

        tools_menu = menubar.addMenu("Outils")
        diff_act = QAction("Comparer configs", self)
        diff_act.triggered.connect(self.compare_configs)
        tools_menu.addAction(diff_act)

        val_act = QAction("Valider config", self)
        val_act.triggered.connect(self.validate_current)
        tools_menu.addAction(val_act)

        # Central
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.tabs_widget = QTabWidget()
        self.tabs_widget.setTabsClosable(True)
        self.tabs_widget.tabCloseRequested.connect(self.close_tab)
        layout.addWidget(self.tabs_widget)

        self.statusBar().showMessage("Prêt. Ouvrez une config.")

        self.add_welcome_tab()

    def add_welcome_tab(self):
        w = QLabel("<h1>Cisco Config Viewer PRO</h1><p>Diff • Validation • SSH • PDF pour IOS XE 17.3.x</p>")
        w.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tabs_widget.addTab(w, "Accueil")

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Ouvrir startup-config", "", "Config (*.cfg *.conf *.txt)")
        if path:
            self.load_config(path)

    def load_config(self, path):
        try:
            text = Path(path).read_text(encoding='utf-8', errors='ignore')
            name = Path(path).stem
            self.create_config_tab(name, text, path)
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))

    def ssh_dialog(self):
        if not ConnectHandler:
            QMessageBox.critical(self, "Erreur", "Installez Netmiko: pip install netmiko")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("SSH vers Catalyst 9200")
        form = QFormLayout(dialog)

        host = QLineEdit("192.168.1.10")
        username = QLineEdit("admin")
        password = QLineEdit("cisco")
        password.setEchoMode(QLineEdit.EchoMode.Password)
        device_type = QComboBox()
        device_type.addItems(["cisco_ios", "cisco_xe"])

        form.addRow("Host:", host)
        form.addRow("User:", username)
        form.addRow("Password:", password)
        form.addRow("Type:", device_type)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            device = {
                'device_type': device_type.currentText(),
                'host': host.text(),
                'username': username.text(),
                'password': password.text(),
            }
            self.ssh_thread = SSHThread(device)
            self.ssh_thread.finished.connect(self.on_ssh_success)
            self.ssh_thread.error.connect(lambda e: QMessageBox.critical(self, "SSH Erreur", e))
            self.ssh_thread.start()
            self.progress.setVisible(True)

    def on_ssh_success(self, config, hostname):
        self.progress.setVisible(False)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{hostname}_{timestamp}.cfg"
        save_path = SAVE_DIR / filename
        save_path.write_text(config, encoding='utf-8')
        self.load_config(str(save_path))

    def create_config_tab(self, name, text, source=None):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Arbre
        tree = QTreeWidget()
        tree.setHeaderLabel("Structure Config")
        tree.setFont(QFont("Consolas", 10))

        # Éditeur (QTextEdit pour simplicité, coloration basique)
        editor = QTextEdit()
        editor.setFont(QFont("Consolas", 10))
        editor.setPlainText(text)
        editor.setReadOnly(True)
        lexer = CiscoLexer()
        lexer.highlight(editor)

        splitter.addWidget(tree)
        splitter.addWidget(editor)
        splitter.setSizes([400, 800])
        layout.addWidget(splitter)

        # Recherche
        search = QLineEdit()
        search.setPlaceholderText("Rechercher...")
        search.textChanged.connect(lambda t: editor.find(t) if t else None)
        layout.addWidget(search)

        # Ajout onglet
        index = self.tabs_widget.addTab(tab, name)
        self.tabs_widget.setCurrentIndex(index)
        self.tabs[name] = {"editor": editor, "tree": tree, "text": text, "source": source}

        # Parsing arbre
        self.parse_tree(tree, text)

    def parse_tree(self, tree, text):
        tree.clear()
        lines = text.splitlines()
        current_group = None
        for line in lines:
            cmd = line.strip()
            if not cmd or cmd.startswith('!'):
                continue
            if cmd.startswith(('interface', 'router', 'vlan')):
                current_group = QTreeWidgetItem([cmd])
                tree.addTopLevelItem(current_group)
            elif current_group and cmd.startswith(('switchport', 'ip ', 'no ')):
                QTreeWidgetItem(current_group, [cmd])

    def compare_configs(self):
        if len(self.tabs) < 2:
            QMessageBox.warning(self, "Diff", "Ouvrez au moins 2 configs.")
            return
        items = list(self.tabs.keys())
        a, ok = QInputDialog.getItem(self, "Diff A", "Choisir:", items, 0, False)
        if not ok: return
        b, ok = QInputDialog.getItem(self, "Diff B", "Choisir:", items, 0, False)
        if not ok or a == b: return

        diff_html = HtmlDiff().make_file(
            self.tabs[a]["text"].splitlines(),
            self.tabs[b]["text"].splitlines(),
            f"Config {a}",
            f"Config {b}"
        )

        diff_tab = QTextEdit()
        diff_tab.setHtml(diff_html)
        self.tabs_widget.addTab(diff_tab, f"Diff {a} vs {b}")

    def validate_current(self):
        current_idx = self.tabs_widget.currentIndex()
        if current_idx < 1:
            QMessageBox.warning(self, "Validation", "Ouvrez une config.")
            return
        name = self.tabs_widget.tabText(current_idx)
        if name not in self.tabs:
            return
        lines = self.tabs[name]["text"].splitlines()

        self.progress.setVisible(True)
        self.val_thread = ValidationThread(lines)
        self.val_thread.finished.connect(lambda issues, stats: self.show_report(name, issues, stats))
        self.val_thread.start()

    def show_report(self, name, issues, stats):
        self.progress.setVisible(False)

        # Générer HTML avec Jinja
        env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        template = env.get_template("report.html")
        html = template.render(hostname=name, date=datetime.now().strftime("%Y-%m-%d %H:%M"), stats=stats, issues=issues)

        report_tab = QTextEdit()
        report_tab.setHtml(html)

        # Export PDF
        export_act = QAction("Exporter PDF", self)
        export_act.triggered.connect(lambda: self.export_pdf(html, f"rapport_{name}.pdf"))
        self.tabs_widget.addTab(report_tab, f"Rapport {name}")
        self.tabs_widget.setTabToolTip(self.tabs_widget.count() - 1, "Clic droit pour exporter")

    def export_pdf(self, html_content, filename):
        path, _ = QFileDialog.getSaveFileName(self, "Exporter PDF", filename, "PDF (*.pdf)")
        if path:
            HTML(string=html_content).write_pdf(path)
            self.statusBar().showMessage(f"PDF sauvé: {path}")

    def close_tab(self, index):
        if index == 0: return
        self.tabs_widget.removeTab(index)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CiscoConfigViewerPro()
    window.show()
    sys.exit(app.exec())
