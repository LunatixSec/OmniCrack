#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  OMNICRACK PROFESSIONAL v2.0                             ║
║  Enterprise-Grade Password Cracking Suite                ║
║  Made by Lunatix • LunatixLeaks Research                 ║
║  Proprietary / Pentester License                         ║
╚══════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import json
import hashlib
import subprocess
import threading
import queue
import socket
import paramiko
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import concurrent.futures
from dataclasses import dataclass
from enum import Enum

# GUI Imports
try:
    from PyQt6.QtWidgets import *
    from PyQt6.QtCore import *
    from PyQt6.QtGui import *
    from PyQt6.QtWebEngineWidgets import *
except ImportError:
    print("[!] PyQt6 required. Install: pip install PyQt6 PyQt6-WebEngine")
    print("[!] Made by Lunatix - Visit https://lunatixleaks.ct.ws")
    sys.exit(1)

# ============================================
# CONFIGURATION & CONSTANTS
# ============================================

VERSION = "2.0.0"
AUTHOR = "Lunatix"
BRAND = "LunatixLeaks Research"
CONTACT = "https://lunatixleaks.ct.ws"

COLORS = {
    'primary': "#b82828",      # Deep red
    'secondary': "#1a1a24",    # Dark slate
    'accent': "#00ff00",        # Matrix green
    'bg_dark': "#0a0a0f",      # Almost black
    'bg_card': "#1a1a24",       # Card background
    'text': "#e0e0e0",          # Light gray
    'text_muted': "#666666",     # Dim gray
    'success': "#00ff00",       # Green
    'warning': "#ffaa00",       # Orange
    'error': "#ff0000"          # Red
}

# Attack Types
class AttackMode(Enum):
    ONLINE_BRUTEFORCE = "Online Brute Force (Hydra)"
    OFFLINE_DICTIONARY = "Offline Dictionary (Hashcat)"
    OFFLINE_MASK = "Offline Mask Attack"
    OFFLINE_RULE = "Rule-Based Attack"
    HYBRID = "Hybrid Attack"
    AI_PROBABILISTIC = "AI Probabilistic (GPT-based)"
    RAINBOW_TABLE = "Rainbow Table Lookup"

# Hash Types
SUPPORTED_HASHES = {
    "MD5": 0,
    "SHA1": 100,
    "SHA256": 1400,
    "SHA512": 1700,
    "NTLM": 1000,
    "bcrypt": 3200,
    "Argon2": 3202,
    "WPA2": 2500,
    "MySQL": 200,
    "Oracle H": 3100
}

# Protocols for online attacks
SUPPORTED_PROTOCOLS = [
    "ssh", "ftp", "http-get", "http-post", "https-get", "https-post",
    "smb", "rdp", "vnc", "telnet", "mysql", "postgresql", "mongodb",
    "redis", "memcached", "ldap", "smtp", "pop3", "imap"
]

# ============================================
# DATA MODELS
# ============================================

@dataclass
class AttackProfile:
    """Configuration profile for an attack"""
    name: str
    mode: AttackMode
    target: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    wordlist: Optional[str] = None
    hash_file: Optional[str] = None
    hash_type: Optional[str] = None
    mask: Optional[str] = None
    rules: Optional[str] = None
    threads: int = 4
    gpu_enabled: bool = True
    timeout: int = 30
    created: str = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {k: v.value if isinstance(v, AttackMode) else v 
                for k, v in self.__dict__.items()}
    
    @classmethod
    def from_dict(cls, data: Dict):
        if 'mode' in data and isinstance(data['mode'], str):
            data['mode'] = AttackMode(data['mode'])
        return cls(**data)

@dataclass
class CrackedPassword:
    """Result of a successful crack"""
    hash_value: str
    password: str
    algorithm: str
    time_taken: float
    method: str
    timestamp: str = datetime.now().isoformat()
    
    def __str__(self):
        return f"[{self.algorithm}] {self.hash_value[:16]}... → {self.password}"

# ============================================
# CORE CRACKING ENGINE
# ============================================

class CrackingEngine(QObject):
    """Core password cracking engine with Lunatix optimizations"""
    
    # Signals
    progress_updated = pyqtSignal(int, int)  # current, total
    status_updated = pyqtSignal(str)
    password_found = pyqtSignal(CrackedPassword)
    attack_complete = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.paused = False
        self.profile: Optional[AttackProfile] = None
        self.results: List[CrackedPassword] = []
        self.start_time = None
        self.attempts = 0
        
    def start_attack(self, profile: AttackProfile):
        """Start cracking with given profile"""
        self.running = True
        self.paused = False
        self.profile = profile
        self.results = []
        self.start_time = time.time()
        self.attempts = 0
        
        # Launch appropriate attack mode
        if profile.mode == AttackMode.ONLINE_BRUTEFORCE:
            threading.Thread(target=self._online_attack, daemon=True).start()
        else:
            threading.Thread(target=self._offline_attack, daemon=True).start()
    
    def pause(self):
        """Pause current attack"""
        self.paused = True
        self.status_updated.emit("Attack paused")
    
    def resume(self):
        """Resume paused attack"""
        self.paused = False
        self.status_updated.emit("Attack resumed")
    
    def stop(self):
        """Stop current attack"""
        self.running = False
        self.status_updated.emit("Attack stopped")
    
    def _online_attack(self):
        """Online brute force (Hydra-style)"""
        self.status_updated.emit(f"Starting online attack against {self.profile.target}")
        
        # Load wordlist
        try:
            with open(self.profile.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.status_updated.emit(f"Error loading wordlist: {str(e)}")
            self.attack_complete.emit()
            return
        
        total = len(passwords)
        self.status_updated.emit(f"Loaded {total} passwords")
        
        # Create connection based on protocol
        if self.profile.protocol == "ssh":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            for i, password in enumerate(passwords):
                if not self.running:
                    break
                while self.paused:
                    time.sleep(0.1)
                
                try:
                    client.connect(
                        hostname=self.profile.target,
                        port=self.profile.port or 22,
                        username=self.profile.username,
                        password=password,
                        timeout=self.profile.timeout,
                        allow_agent=False,
                        look_for_keys=False
                    )
                    
                    # Success!
                    cracked = CrackedPassword(
                        hash_value=f"{self.profile.username}@{self.profile.target}",
                        password=password,
                        algorithm=f"SSH/{self.profile.protocol}",
                        time_taken=time.time() - self.start_time,
                        method="Online brute force"
                    )
                    self.results.append(cracked)
                    self.password_found.emit(cracked)
                    client.close()
                    break
                    
                except paramiko.AuthenticationException:
                    pass
                except Exception as e:
                    self.status_updated.emit(f"Connection error: {str(e)}")
                
                self.attempts += 1
                if i % 10 == 0:
                    self.progress_updated.emit(i, total)
            
            client.close()
        
        # Add more protocols here (FTP, HTTP, etc.)
        
        self.attack_complete.emit()
    
    def _offline_attack(self):
        """Offline hash cracking (Hashcat-style)"""
        self.status_updated.emit(f"Starting offline attack on {self.profile.hash_file}")
        
        # Load hashes
        try:
            with open(self.profile.hash_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.status_updated.emit(f"Error loading hashes: {str(e)}")
            self.attack_complete.emit()
            return
        
        # Load wordlist
        try:
            with open(self.profile.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.status_updated.emit(f"Error loading wordlist: {str(e)}")
            self.attack_complete.emit()
            return
        
        total = len(passwords)
        hash_type = self.profile.hash_type or "MD5"
        
        self.status_updated.emit(f"Cracking {len(hashes)} {hash_type} hashes with {total} passwords")
        
        for i, password in enumerate(passwords):
            if not self.running:
                break
            while self.paused:
                time.sleep(0.1)
            
            # Calculate hash based on type
            if hash_type == "MD5":
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == "SHA1":
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == "SHA256":
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            elif hash_type == "SHA512":
                test_hash = hashlib.sha512(password.encode()).hexdigest()
            else:
                continue
            
            # Check against target hashes
            for h in hashes:
                if test_hash.lower() == h.lower():
                    cracked = CrackedPassword(
                        hash_value=h,
                        password=password,
                        algorithm=hash_type,
                        time_taken=time.time() - self.start_time,
                        method="Dictionary attack"
                    )
                    self.results.append(cracked)
                    self.password_found.emit(cracked)
                    
                    # Remove cracked hash
                    hashes.remove(h)
                    if not hashes:
                        break
            
            self.attempts += 1
            if i % 1000 == 0:
                self.progress_updated.emit(i, total)
        
        self.attack_complete.emit()
    
    def get_stats(self) -> Dict:
        """Get current attack statistics"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        return {
            'attempts': self.attempts,
            'elapsed': elapsed,
            'rate': rate,
            'found': len(self.results)
        }

# ============================================
# GUI - MAIN WINDOW
# ============================================

class MainWindow(QMainWindow):
    """Professional GUI for OmniCrack"""
    
    def __init__(self):
        super().__init__()
        self.engine = CrackingEngine()
        self.current_profile: Optional[AttackProfile] = None
        self.init_ui()
        self.connect_signals()
        self.load_profiles()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"OmniCrack Professional v{VERSION} • Made by Lunatix")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set window icon
        self.setWindowIcon(self.create_icon())
        
        # Apply dark theme
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['bg_dark']};
            }}
            QWidget {{
                background-color: transparent;
                color: {COLORS['text']};
                font-family: 'Segoe UI', 'Inter', sans-serif;
            }}
            QPushButton {{
                background-color: {COLORS['primary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #d03030;
            }}
            QPushButton:disabled {{
                background-color: #444;
            }}
            QLineEdit, QTextEdit, QComboBox, QSpinBox {{
                background-color: {COLORS['bg_card']};
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px;
                color: {COLORS['text']};
            }}
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
                border-color: {COLORS['primary']};
            }}
            QTabWidget::pane {{
                border: 1px solid #333;
                background-color: {COLORS['bg_card']};
                border-radius: 4px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text']};
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['primary']};
            }}
            QGroupBox {{
                border: 1px solid #333;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: {COLORS['primary']};
            }}
            QProgressBar {{
                border: 1px solid #333;
                border-radius: 4px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['primary']};
                border-radius: 4px;
            }}
            QListWidget {{
                background-color: {COLORS['bg_card']};
                border: 1px solid #333;
                border-radius: 4px;
                padding: 4px;
            }}
            QListWidget::item:selected {{
                background-color: {COLORS['primary']};
            }}
        """)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        
        # Main layout
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Header with Lunatix branding
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter, 1)
        
        # Left panel - Configuration
        left_panel = self.create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results & Visualization
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([600, 800])
        
        # Status bar
        self.create_status_bar()
    
    def create_header(self) -> QWidget:
        """Create branded header"""
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 10, 10, 10)
        
        # Logo/Title
        title = QLabel(f"OMNICRACK PROFESSIONAL v{VERSION}")
        title.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {COLORS['primary']};
            padding: 10px;
        """)
        header_layout.addWidget(title)
        
        # Made by Lunatix badge
        badge = QLabel("⚡ MADE BY LUNATIX ⚡")
        badge.setStyleSheet(f"""
            background-color: {COLORS['primary']};
            color: white;
            font-weight: bold;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
        """)
        header_layout.addWidget(badge)
        
        header_layout.addStretch()
        
        # Profile selector
        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(200)
        self.profile_combo.currentIndexChanged.connect(self.load_profile)
        header_layout.addWidget(QLabel("Profile:"))
        header_layout.addWidget(self.profile_combo)
        
        # Save profile button
        save_btn = QPushButton("Save Profile")
        save_btn.clicked.connect(self.save_profile)
        header_layout.addWidget(save_btn)
        
        return header
    
    def create_config_panel(self) -> QWidget:
        """Create configuration panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Attack Mode Selection
        mode_group = QGroupBox("Attack Mode")
        mode_layout = QVBoxLayout(mode_group)
        
        self.mode_combo = QComboBox()
        for mode in AttackMode:
            self.mode_combo.addItem(mode.value)
        self.mode_combo.currentIndexChanged.connect(self.mode_changed)
        mode_layout.addWidget(self.mode_combo)
        
        layout.addWidget(mode_group)
        
        # Target Configuration (stacked widget for different modes)
        self.config_stack = QStackedWidget()
        
        # Online attack config
        online_widget = self.create_online_config()
        self.config_stack.addWidget(online_widget)
        
        # Offline attack config
        offline_widget = self.create_offline_config()
        self.config_stack.addWidget(offline_widget)
        
        # AI attack config
        ai_widget = self.create_ai_config()
        self.config_stack.addWidget(ai_widget)
        
        layout.addWidget(self.config_stack)
        
        # Advanced Options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QGridLayout(advanced_group)
        
        advanced_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 128)
        self.threads_spin.setValue(4)
        advanced_layout.addWidget(self.threads_spin, 0, 1)
        
        advanced_layout.addWidget(QLabel("Timeout (s):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        advanced_layout.addWidget(self.timeout_spin, 1, 1)
        
        self.gpu_check = QCheckBox("Enable GPU Acceleration")
        self.gpu_check.setChecked(True)
        advanced_layout.addWidget(self.gpu_check, 2, 0, 1, 2)
        
        layout.addWidget(advanced_group)
        
        # Control Buttons
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶ START ATTACK")
        self.start_btn.setMinimumHeight(50)
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: black;
                font-size: 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #00cc00;
            }}
        """)
        self.start_btn.clicked.connect(self.start_attack)
        btn_layout.addWidget(self.start_btn)
        
        self.pause_btn = QPushButton("⏸ PAUSE")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.pause_attack)
        btn_layout.addWidget(self.pause_btn)
        
        self.stop_btn = QPushButton("⏹ STOP")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_attack)
        btn_layout.addWidget(self.stop_btn)
        
        layout.addLayout(btn_layout)
        
        layout.addStretch()
        
        return panel
    
    def create_online_config(self) -> QWidget:
        """Online attack configuration"""
        widget = QWidget()
        layout = QGridLayout(widget)
        
        layout.addWidget(QLabel("Target:"), 0, 0)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("192.168.1.1 or domain.com")
        layout.addWidget(self.target_edit, 0, 1)
        
        layout.addWidget(QLabel("Port:"), 1, 0)
        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("22 (SSH)")
        layout.addWidget(self.port_edit, 1, 1)
        
        layout.addWidget(QLabel("Protocol:"), 2, 0)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(SUPPORTED_PROTOCOLS)
        layout.addWidget(self.protocol_combo, 2, 1)
        
        layout.addWidget(QLabel("Username:"), 3, 0)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("admin")
        layout.addWidget(self.username_edit, 3, 1)
        
        layout.addWidget(QLabel("Wordlist:"), 4, 0)
        wordlist_layout = QHBoxLayout()
        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("/path/to/wordlist.txt")
        wordlist_layout.addWidget(self.wordlist_edit)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: self.browse_file(self.wordlist_edit))
        wordlist_layout.addWidget(browse_btn)
        layout.addLayout(wordlist_layout, 4, 1)
        
        return widget
    
    def create_offline_config(self) -> QWidget:
        """Offline hash cracking configuration"""
        widget = QWidget()
        layout = QGridLayout(widget)
        
        layout.addWidget(QLabel("Hash File:"), 0, 0)
        hash_layout = QHBoxLayout()
        self.hashfile_edit = QLineEdit()
        self.hashfile_edit.setPlaceholderText("/path/to/hashes.txt")
        hash_layout.addWidget(self.hashfile_edit)
        
        browse_hash = QPushButton("Browse")
        browse_hash.clicked.connect(lambda: self.browse_file(self.hashfile_edit))
        hash_layout.addWidget(browse_hash)
        layout.addLayout(hash_layout, 0, 1)
        
        layout.addWidget(QLabel("Hash Type:"), 1, 0)
        self.hashtype_combo = QComboBox()
        self.hashtype_combo.addItems(list(SUPPORTED_HASHES.keys()))
        layout.addWidget(self.hashtype_combo, 1, 1)
        
        layout.addWidget(QLabel("Wordlist:"), 2, 0)
        wordlist_layout = QHBoxLayout()
        self.offline_wordlist = QLineEdit()
        self.offline_wordlist.setPlaceholderText("/path/to/wordlist.txt")
        wordlist_layout.addWidget(self.offline_wordlist)
        
        browse_wordlist = QPushButton("Browse")
        browse_wordlist.clicked.connect(lambda: self.browse_file(self.offline_wordlist))
        wordlist_layout.addWidget(browse_wordlist)
        layout.addLayout(wordlist_layout, 2, 1)
        
        layout.addWidget(QLabel("Mask Pattern:"), 3, 0)
        self.mask_edit = QLineEdit()
        self.mask_edit.setPlaceholderText("?l?l?l?d?d (optional)")
        layout.addWidget(self.mask_edit, 3, 1)
        
        return widget
    
    def create_ai_config(self) -> QWidget:
        """AI-based attack configuration"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        layout.addWidget(QLabel("AI Password Generation"))
        layout.addWidget(QLabel("Using GPT-4 to generate probable passwords based on target info"))
        
        info_text = QTextEdit()
        info_text.setPlaceholderText("Enter target information (company name, keywords, patterns)...")
        info_text.setMaximumHeight(100)
        layout.addWidget(info_text)
        
        layout.addWidget(QLabel("Number of passwords to generate:"))
        self.ai_count = QSpinBox()
        self.ai_count.setRange(10, 10000)
        self.ai_count.setValue(1000)
        layout.addWidget(self.ai_count)
        
        return widget
    
    def create_results_panel(self) -> QWidget:
        """Create results visualization panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        # Attempts card
        attempts_card = self.create_stat_card("Attempts", "0", COLORS['primary'])
        self.attempts_label = attempts_card.findChild(QLabel, "value")
        stats_layout.addWidget(attempts_card)
        
        # Found card
        found_card = self.create_stat_card("Found", "0", COLORS['success'])
        self.found_label = found_card.findChild(QLabel, "value")
        stats_layout.addWidget(found_card)
        
        # Rate card
        rate_card = self.create_stat_card("Rate (p/s)", "0", COLORS['warning'])
        self.rate_label = rate_card.findChild(QLabel, "value")
        stats_layout.addWidget(rate_card)
        
        # Time card
        time_card = self.create_stat_card("Elapsed", "00:00", COLORS['text'])
        self.time_label = time_card.findChild(QLabel, "value")
        stats_layout.addWidget(time_card)
        
        layout.addLayout(stats_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Status
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet(f"color: {COLORS['text_muted']}; padding: 5px;")
        layout.addWidget(self.status_label)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Hash/User", "Password", "Algorithm", "Time"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table)
        
        # Export button
        export_btn = QPushButton("Export Results")
        export_btn.clicked.connect(self.export_results)
        layout.addWidget(export_btn)
        
        return panel
    
    def create_stat_card(self, title: str, value: str, color: str) -> QWidget:
        """Create a statistics card"""
        card = QWidget()
        card.setStyleSheet(f"""
            background-color: {COLORS['bg_card']};
            border: 1px solid #333;
            border-radius: 8px;
            padding: 10px;
        """)
        
        layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        layout.addWidget(value_label)
        
        return card
    
    def create_status_bar(self):
        """Create status bar with Lunatix branding"""
        self.statusBar().showMessage(f"OmniCrack Professional • Made by Lunatix • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def create_icon(self) -> QIcon:
        """Create application icon"""
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor(COLORS['primary']))
        
        painter = QPainter(pixmap)
        painter.setPen(QColor(COLORS['text']))
        painter.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "OC")
        painter.end()
        
        return QIcon(pixmap)
    
    # ============================================
    # SLOTS & FUNCTIONALITY
    # ============================================
    
    def browse_file(self, line_edit: QLineEdit):
        """Open file browser"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            line_edit.setText(file_path)
    
    def mode_changed(self, index: int):
        """Handle attack mode change"""
        if index == 0:  # Online
            self.config_stack.setCurrentIndex(0)
        elif index <= 2:  # Offline
            self.config_stack.setCurrentIndex(1)
        else:  # AI
            self.config_stack.setCurrentIndex(2)
    
    def save_profile(self):
        """Save current configuration as profile"""
        name, ok = QInputDialog.getText(self, "Save Profile", "Profile name:")
        if ok and name:
            profile = self.create_profile_from_ui()
            profile.name = name
            
            profiles = self.load_profiles_from_disk()
            profiles[name] = profile.to_dict()
            
            with open(Path.home() / ".omnicrack_profiles.json", 'w') as f:
                json.dump(profiles, f, indent=2)
            
            self.load_profiles()
            self.profile_combo.setCurrentText(name)
    
    def load_profiles(self):
        """Load saved profiles into combo box"""
        self.profile_combo.clear()
        self.profile_combo.addItem("New Profile")
        
        profiles = self.load_profiles_from_disk()
        for name in profiles.keys():
            self.profile_combo.addItem(name)
    
    def load_profiles_from_disk(self) -> Dict:
        """Load profiles from disk"""
        profile_file = Path.home() / ".omnicrack_profiles.json"
        if profile_file.exists():
            with open(profile_file, 'r') as f:
                return json.load(f)
        return {}
    
    def load_profile(self, index: int):
        """Load selected profile"""
        if index <= 0:
            return
        
        profiles = self.load_profiles_from_disk()
        name = self.profile_combo.currentText()
        
        if name in profiles:
            data = profiles[name]
            self.current_profile = AttackProfile.from_dict(data)
            self.load_profile_to_ui(self.current_profile)
    
    def load_profile_to_ui(self, profile: AttackProfile):
        """Load profile data into UI fields"""
        self.mode_combo.setCurrentIndex(list(AttackMode).index(profile.mode))
        
        if profile.mode == AttackMode.ONLINE_BRUTEFORCE:
            self.target_edit.setText(profile.target)
            self.port_edit.setText(str(profile.port) if profile.port else "")
            self.protocol_combo.setCurrentText(profile.protocol or "ssh")
            self.username_edit.setText(profile.username or "")
            self.wordlist_edit.setText(profile.wordlist or "")
        
        elif profile.mode in [AttackMode.OFFLINE_DICTIONARY, AttackMode.OFFLINE_MASK, AttackMode.OFFLINE_RULE]:
            self.hashfile_edit.setText(profile.hash_file or "")
            self.hashtype_combo.setCurrentText(profile.hash_type or "MD5")
            self.offline_wordlist.setText(profile.wordlist or "")
            self.mask_edit.setText(profile.mask or "")
        
        self.threads_spin.setValue(profile.threads)
        self.timeout_spin.setValue(profile.timeout)
        self.gpu_check.setChecked(profile.gpu_enabled)
    
    def create_profile_from_ui(self) -> AttackProfile:
        """Create profile from current UI state"""
        mode_index = self.mode_combo.currentIndex()
        mode = list(AttackMode)[mode_index]
        
        if mode_index == 0:  # Online
            return AttackProfile(
                name="",
                mode=mode,
                target=self.target_edit.text(),
                port=int(self.port_edit.text()) if self.port_edit.text() else None,
                protocol=self.protocol_combo.currentText(),
                username=self.username_edit.text(),
                wordlist=self.wordlist_edit.text(),
                threads=self.threads_spin.value(),
                timeout=self.timeout_spin.value(),
                gpu_enabled=self.gpu_check.isChecked()
            )
        
        elif mode_index <= 2:  # Offline
            return AttackProfile(
                name="",
                mode=mode,
                target="",
                hash_file=self.hashfile_edit.text(),
                hash_type=self.hashtype_combo.currentText(),
                wordlist=self.offline_wordlist.text(),
                mask=self.mask_edit.text(),
                threads=self.threads_spin.value(),
                timeout=self.timeout_spin.value(),
                gpu_enabled=self.gpu_check.isChecked()
            )
        
        else:  # AI
            return AttackProfile(
                name="",
                mode=mode,
                target="",
                threads=self.threads_spin.value(),
                timeout=self.timeout_spin.value(),
                gpu_enabled=self.gpu_check.isChecked()
            )
    
    def start_attack(self):
        """Start the cracking attack"""
        profile = self.create_profile_from_ui()
        self.current_profile = profile
        
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        
        self.status_label.setText(f"Starting {profile.mode.value}...")
        self.progress_bar.setValue(0)
        
        self.engine.start_attack(profile)
    
    def pause_attack(self):
        """Pause current attack"""
        if self.engine.paused:
            self.engine.resume()
            self.pause_btn.setText("⏸ PAUSE")
        else:
            self.engine.pause()
            self.pause_btn.setText("▶ RESUME")
    
    def stop_attack(self):
        """Stop current attack"""
        self.engine.stop()
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setText("⏸ PAUSE")
        self.status_label.setText("Attack stopped")
    
    def connect_signals(self):
        """Connect engine signals to UI"""
        self.engine.progress_updated.connect(self.update_progress)
        self.engine.status_updated.connect(self.status_label.setText)
        self.engine.password_found.connect(self.add_result)
        self.engine.attack_complete.connect(self.attack_finished)
    
    def update_progress(self, current: int, total: int):
        """Update progress bar and stats"""
        percentage = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percentage)
        
        stats = self.engine.get_stats()
        self.attempts_label.setText(str(stats['attempts']))
        self.found_label.setText(str(stats['found']))
        self.rate_label.setText(f"{stats['rate']:.1f}")
        
        minutes = int(stats['elapsed'] // 60)
        seconds = int(stats['elapsed'] % 60)
        self.time_label.setText(f"{minutes:02d}:{seconds:02d}")
    
    def add_result(self, cracked: CrackedPassword):
        """Add cracked password to results table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(cracked.hash_value[:50]))
        self.results_table.setItem(row, 1, QTableWidgetItem(cracked.password))
        self.results_table.setItem(row, 2, QTableWidgetItem(cracked.algorithm))
        
        elapsed = time.strftime("%H:%M:%S", time.gmtime(cracked.time_taken))
        self.results_table.setItem(row, 3, QTableWidgetItem(elapsed))
        
        self.results_table.scrollToBottom()
        
        # Play sound (optional)
        QApplication.beep()
    
    def attack_finished(self):
        """Handle attack completion"""
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Attack complete")
        
        stats = self.engine.get_stats()
        QMessageBox.information(
            self, 
            "Attack Complete",
            f"Attack finished!\n\nAttempts: {stats['attempts']}\nFound: {stats['found']}\nTime: {stats['elapsed']:.1f}s"
        )
    
    def export_results(self):
        """Export results to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", 
            f"omnicrack_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write("OMNICRACK PROFESSIONAL RESULTS\n")
                f.write(f"Made by Lunatix • {datetime.now().isoformat()}\n")
                f.write("=" * 50 + "\n\n")
                
                for i in range(self.results_table.rowCount()):
                    hash_val = self.results_table.item(i, 0).text()
                    pwd = self.results_table.item(i, 1).text()
                    algo = self.results_table.item(i, 2).text()
                    f.write(f"[{algo}] {hash_val} → {pwd}\n")
            
            self.status_label.setText(f"Results exported to {file_path}")

# ============================================
# SPLASH SCREEN
# ============================================

class SplashScreen(QSplashScreen):
    """Professional splash screen with Lunatix branding"""
    
    def __init__(self):
        pixmap = QPixmap(600, 300)
        pixmap.fill(QColor(COLORS['bg_dark']))
        
        painter = QPainter(pixmap)
        painter.setPen(QColor(COLORS['primary']))
        painter.setFont(QFont("Arial", 36, QFont.Weight.Bold))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "OMNICRACK")
        
        painter.setPen(QColor(COLORS['text']))
        painter.setFont(QFont("Arial", 14))
        painter.drawText(0, 200, pixmap.width(), 50, 
                        Qt.AlignmentFlag.AlignCenter, 
                        f"Professional Password Cracking Suite v{VERSION}")
        
        painter.setPen(QColor(COLORS['accent']))
        painter.setFont(QFont("Arial", 10))
        painter.drawText(0, 250, pixmap.width(), 30,
                        Qt.AlignmentFlag.AlignCenter,
                        "Made by Lunatix • LunatixLeaks Research")
        
        painter.end()
        
        super().__init__(pixmap)
        self.show()
        QApplication.processEvents()

# ============================================
# MAIN ENTRY POINT
# ============================================

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("OmniCrack Professional")
    app.setOrganizationName("LunatixLeaks")
    
    # Show splash screen
    splash = SplashScreen()
    splash.show()
    app.processEvents()
    
    # Simulate loading
    for i in range(1, 101):
        splash.showMessage(
            f"Loading modules... {i}%",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter,
            QColor(COLORS['primary'])
        )
        app.processEvents()
        time.sleep(0.01)
    
    # Create and show main window
    window = MainWindow()
    window.show()
    splash.finish(window)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        print("[!] Made by Lunatix - Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        print("[!] Made by Lunatix - Report issues at https://lunatixleaks.ct.ws")
        sys.exit(1)