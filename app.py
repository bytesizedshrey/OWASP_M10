import sys
import os
import zipfile
import subprocess
import logging
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QMessageBox, QProgressBar,
                             QFrame, QScrollArea, QDialog, QTextBrowser, QTabWidget, QGraphicsDropShadowEffect)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette, QLinearGradient, QBrush
from androguard.misc import AnalyzeAPK
from androguard.core.dex import EncodedMethod
from androguard.core.axml import AXMLPrinter
from lxml import etree
import tempfile
import webbrowser
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import platform
import glob
import plistlib

# Silence debug logs
logging.basicConfig(level=logging.ERROR)
logging.getLogger("androguard").setLevel(logging.ERROR)

# Premium color palette
BACKGROUND_COLOR = "#121212"
CARD_COLOR = "#1E1E1E"
ACCENT_COLOR = "#6200EA"
HOVER_COLOR = "#BB86FC"
TEXT_COLOR = "#E0E0E0"
ERROR_COLOR = "#CF6679"
SUCCESS_COLOR = "#03DAC6"

# Path to apktool
APKTOOL_PATH = "apktool.jar"

# Supported APK-like extensions
APK_EXTENSIONS = ['.apk', '.xapk', '.apkm', '.apks']  # Add more as needed

class AnalysisThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(list, list)

    def __init__(self, file_path, file_type):
        super().__init__()
        self.file_path = file_path
        self.file_type = file_type
        self.temp_dir = None
        self.decompile_dir = None

    def run(self):
        try:
            if self.file_type in [ext[1:] for ext in APK_EXTENSIONS]:  # Strip '.' from extensions
                apk_file = self.extract_apk_variant()
                if not apk_file:
                    self.finished_signal.emit([f"Failed to extract {self.file_type.upper()}"], [])
                    return
                summarized_vulns, full_vulns = self.static_analysis_apk(apk_file)
            elif self.file_type == 'ipa':
                summarized_vulns, full_vulns = self.static_analysis_ipa()
            else:
                summarized_vulns, full_vulns = ["Unsupported file type"], []
            self.finished_signal.emit(summarized_vulns, full_vulns)
        except MemoryError:
            self.update_signal.emit("Memory limit hit, switching to lightweight mode...")
            summarized_vulns, full_vulns = self.lightweight_analysis()
            self.finished_signal.emit(summarized_vulns, full_vulns)
        except Exception as e:
            self.finished_signal.emit([f"Analysis failed: {str(e)}"], [])
        finally:
            self.cleanup()

    def extract_apk_variant(self):
        """Extract APK from any APK-like variant (APK, XAPK, APKM, etc.)."""
        self.update_signal.emit(f"Unpacking {self.file_type.upper()}...")
        if self.file_type == 'apk':
            return self.file_path  # Single APK, no extraction needed
        
        self.temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(self.file_path, 'r') as z:
                apk_files = [f for f in z.infolist() if f.filename.endswith('.apk')]
                if not apk_files:
                    return None
                # Look for a base APK or the first APK in the bundle
                base_apk = next((f for f in apk_files if 'base' in f.filename.lower()), apk_files[0])
                extracted_path = z.extract(base_apk, self.temp_dir)
                self.update_signal.emit(f"Extracted APK: {os.path.basename(extracted_path)}")
                return extracted_path
        except zipfile.BadZipFile:
            self.update_signal.emit(f"Invalid {self.file_type.upper()} file")
            return None

    def cleanup(self):
        for dir_path in [self.temp_dir, self.decompile_dir]:
            if dir_path and os.path.exists(dir_path):
                for root, dirs, files in os.walk(dir_path, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(dir_path)

    def decompile_apk(self, apk_file):
        self.update_signal.emit("Decompiling APK...")
        self.decompile_dir = tempfile.mkdtemp()
        try:
            if not os.path.exists(APKTOOL_PATH):
                raise FileNotFoundError(f"apktool.jar not found at {APKTOOL_PATH}")
            subprocess.run(['java', '-jar', APKTOOL_PATH, 'd', apk_file, '-f', '-o', self.decompile_dir], 
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.update_signal.emit("APK decompiled successfully.")
            return self.decompile_dir
        except Exception as e:
            self.update_signal.emit(f"Failed to decompile APK: {str(e)}")
            return None

    def analyze_dex(self, dx):
        self.update_signal.emit("Checking DEX files...")
        vulnerabilities = set()
        sample_count = 0
        max_samples = 1000  # Limit for efficiency

        for cls in dx.get_classes():
            for method in cls.get_methods():
                if sample_count >= max_samples:
                    self.update_signal.emit("Sampling limit reached, skipping remaining methods...")
                    break
                try:
                    raw_method = method.get_method()
                    if isinstance(raw_method, EncodedMethod) and raw_method.get_code():
                        instructions = list(raw_method.get_code().get_bc().get_instructions())
                        class_name = cls.get_vm_class().get_name()
                        for i, ins in enumerate(instructions[:100]):  # Limit instructions per method
                            ins_str = ins.get_name() + " " + " ".join(map(str, ins.get_operands()))
                            for weak in ['des', 'md5', 'sha1', 'rc4', 'sha', '3des', 'rc2', 'blowfish']:
                                if weak in ins_str.lower():
                                    vulnerabilities.add(f"Detected weak algorithm '{weak.upper()}' in {class_name}")
                            if 'Ljavax/crypto/KeyGenerator' in ins_str or 'Ljava/security/KeyPairGenerator' in ins_str:
                                for j in range(i, min(i + 5, len(instructions))):
                                    next_ins = instructions[j]
                                    operands = next_ins.get_operands()
                                    for op in operands:
                                        if isinstance(op, tuple) and op[0] == 'CONST':
                                            key_length = op[1]
                                            if 'aes' in ins_str.lower() and key_length < 128:
                                                vulnerabilities.add(f"Insufficient key length ({key_length} bits) for AES in {class_name}")
                                            elif 'rsa' in ins_str.lower() and key_length < 2048:
                                                vulnerabilities.add(f"Insufficient key length ({key_length} bits) for RSA in {class_name}")
                                            elif 'des' in ins_str.lower() and key_length <= 56:
                                                vulnerabilities.add(f"Insufficient key length ({key_length} bits) for DES in {class_name}")
                        sample_count += 1
                        if sample_count % 100 == 0:
                            self.update_signal.emit(f"Processed {sample_count} methods...")
                except Exception:
                    continue
            if sample_count >= max_samples:
                break
        return list(vulnerabilities)

    def analyze_manifest(self, apk):
        self.update_signal.emit("Checking AndroidManifest.xml...")
        vulnerabilities = set()
        try:
            manifest_xml = apk.get_android_manifest_xml()
            manifest_str = etree.tostring(manifest_xml, encoding='unicode').lower()
        except Exception:
            raw_manifest = apk.get_file('AndroidManifest.xml')
            axml = AXMLPrinter(raw_manifest)
            manifest_str = axml.get_buff().decode('utf-8', errors='ignore')

        if 'android.permission.write_external_storage' in manifest_str:
            vulnerabilities.add("Insecure storage permission (WRITE_EXTERNAL_STORAGE) detected.")
        if 'android.permission.internet' in manifest_str and 'usescleartexttraffic="false"' not in manifest_str:
            vulnerabilities.add("Potential cleartext traffic (non-HTTPS) detected.")
        return list(vulnerabilities)

    def scan_smali_files(self, decompile_dir):
        self.update_signal.emit("Scanning Smali files...")
        vulnerabilities = set()
        weak_algorithms = {'des', 'md5', 'sha1', 'rc4', 'sha', '3des', 'rc2', 'blowfish'}
        smali_files = glob.glob(os.path.join(decompile_dir, '**', '*.smali'), recursive=True)
        
        for smali_file in smali_files[:1000]:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024 * 1024)
                    content_lower = content.lower()
                    lines = content_lower.split('\n')
                    for weak in weak_algorithms:
                        if weak in content_lower:
                            vulnerabilities.add(f"Detected weak algorithm '{weak.upper()}' in Smali file: {os.path.basename(smali_file)}")
                    if 'const-string' in content_lower and 'key' in content_lower:
                        vulnerabilities.add(f"Possible hardcoded key in Smali file: {os.path.basename(smali_file)}")
            except Exception:
                continue
        return list(vulnerabilities)

    def static_analysis_apk(self, apk_file):
        apk, _, dx = AnalyzeAPK(apk_file)
        vulnerabilities = set()
        
        dex_vulns = self.analyze_dex(dx)
        vulnerabilities.update(dex_vulns)
        
        manifest_vulns = self.analyze_manifest(apk)
        vulnerabilities.update(manifest_vulns)
        
        decompile_dir = self.decompile_apk(apk_file)
        if decompile_dir:
            smali_vulns = self.scan_smali_files(decompile_dir)
            vulnerabilities.update(smali_vulns)
        
        summarized_vulns = set()
        weak_algos = set()
        for vuln in vulnerabilities:
            if "weak algorithm" in vuln.lower():
                algo = vuln.split("'")[1]
                weak_algos.add(algo)
            elif "insufficient key length" in vuln.lower():
                summarized_vulns.add("Insufficient Key Lengths detected [Insufficient Key Length]")
            elif "hardcoded key" in vuln.lower():
                summarized_vulns.add("Possible Hardcoded Keys detected")
            elif "permission" in vuln.lower() or "cleartext" in vuln.lower():
                summarized_vulns.add("Insecure Permissions or Settings detected")
            else:
                summarized_vulns.add(vuln)
        
        if weak_algos:
            algo_list = ", ".join(sorted(weak_algos))
            summarized_vulns.add(f"Weak Encryption Algorithms detected ({algo_list})")
        
        return list(summarized_vulns), list(vulnerabilities)

    def static_analysis_ipa(self):
        self.update_signal.emit("Analyzing IPA (static)...")
        vulnerabilities = set()
        self.temp_dir = tempfile.mkdtemp()

        try:
            with zipfile.ZipFile(self.file_path, 'r') as z:
                z.extractall(self.temp_dir)

            info_plist_path = os.path.join(self.temp_dir, "Payload", "*.app", "Info.plist")
            info_plist_files = glob.glob(info_plist_path)
            if info_plist_files:
                with open(info_plist_files[0], 'rb') as f:
                    info_plist = plistlib.load(f)
                    if info_plist.get('NSAppTransportSecurity', {}).get('NSAllowsArbitraryLoads', False):
                        vulnerabilities.add("Potential cleartext traffic (non-HTTPS) detected.")
                    if info_plist.get('NSCameraUsageDescription') or info_plist.get('NSPhotoLibraryUsageDescription'):
                        vulnerabilities.add("Insecure storage permission detected (Camera/Photo access).")
            
            summarized_vulns = set(vulnerabilities)
            return list(summarized_vulns), list(vulnerabilities)
        except Exception as e:
            return [f"Error analyzing IPA: {str(e)}"], []

    def lightweight_analysis(self):
        """Fallback analysis for large files with memory issues."""
        vulnerabilities = set()
        if self.file_type in [ext[1:] for ext in APK_EXTENSIONS]:
            vulnerabilities.add(f"Lightweight mode: Limited analysis for {self.file_type.upper()} due to file size.")
        elif self.file_type == 'ipa':
            vulnerabilities.add("Lightweight mode: Only basic checks performed.")
        return list(vulnerabilities), list(vulnerabilities)

class CipherWraith(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CipherWraith Analyzer")
        self.setGeometry(100, 100, 1100, 750)
        self.full_vulnerabilities = []
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {BACKGROUND_COLOR}, stop:1 #212121);")
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)

        # Sidebar
        sidebar = QFrame()
        sidebar.setStyleSheet(f"background: {CARD_COLOR}; border-radius: 15px; border: 1px solid {ACCENT_COLOR};")
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(12)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 4)
        sidebar.setGraphicsEffect(shadow)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 15, 15, 15)
        sidebar_layout.setSpacing(15)

        nav_items = ["How to Use", "Export PDF", "Share", "Email"]
        nav_functions = {"How to Use": self.show_how_to_use, "Export PDF": self.export_pdf, "Share": self.share_results, "Email": self.email_results}
        for item in nav_items:
            nav_button = QPushButton(item)
            nav_button.setFont(QFont("Arial", 12, QFont.Weight.Medium))
            nav_button.setStyleSheet(f"""
                QPushButton {{background: {CARD_COLOR}; color: {TEXT_COLOR}; border: none; padding: 12px 20px; border-radius: 10px; text-align: left;}}
                QPushButton:hover {{background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_COLOR}, stop:1 {HOVER_COLOR}); color: #FFFFFF;}}
            """)
            if item in nav_functions:
                nav_button.clicked.connect(nav_functions[item])
            sidebar_layout.addWidget(nav_button)
        sidebar_layout.addStretch()
        layout.addWidget(sidebar, stretch=1)

        # Main content
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(20)

        # Header
        header_frame = QFrame()
        header_frame.setStyleSheet(f"background: {CARD_COLOR}; border-radius: 15px; border: 1px solid {ACCENT_COLOR};")
        header_frame.setGraphicsEffect(shadow)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 15, 20, 15)

        logo_label = QLabel("CipherWraith")
        logo_label.setFont(QFont("Arial", 26, QFont.Weight.Bold))
        logo_label.setStyleSheet(f"color: {HOVER_COLOR};")
        header_layout.addWidget(logo_label)

        self.static_status = QLabel("Ready")
        self.static_status.setFont(QFont("Arial", 12, QFont.Weight.Light))
        self.static_status.setStyleSheet(f"color: {TEXT_COLOR};")
        header_layout.addStretch()
        header_layout.addWidget(self.static_status)

        profile_icon = QLabel("👤")
        profile_icon.setFont(QFont("Arial", 20))
        profile_icon.setStyleSheet(f"color: {TEXT_COLOR}; padding: 5px;")
        header_layout.addWidget(profile_icon)
        content_layout.addWidget(header_frame)

        # Control panel
        control_frame = QFrame()
        control_frame.setStyleSheet(f"background: {CARD_COLOR}; border-radius: 15px; border: 1px solid {ACCENT_COLOR};")
        control_frame.setGraphicsEffect(shadow)
        control_layout = QVBoxLayout(control_frame)
        control_layout.setContentsMargins(20, 20, 20, 20)
        control_layout.setSpacing(15)

        file_tile = QFrame()
        file_tile.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_COLOR}, stop:1 {HOVER_COLOR}); border-radius: 12px; padding: 10px;")
        file_layout = QHBoxLayout(file_tile)
        file_icon = QLabel("📁")
        file_icon.setFont(QFont("Arial", 20))
        file_icon.setStyleSheet(f"color: #FFFFFF; padding: 5px;")
        file_layout.addWidget(file_icon)

        self.file_label = QLabel("Select an App File")
        self.file_label.setFont(QFont("Arial", 14, QFont.Weight.Medium))
        self.file_label.setStyleSheet(f"color: #FFFFFF;")
        file_layout.addWidget(self.file_label)
        file_layout.addStretch()

        browse_button = QPushButton("Browse")
        browse_button.setFont(QFont("Arial", 12, QFont.Weight.Medium))
        browse_button.setStyleSheet(f"""
            QPushButton {{background: rgba(255, 255, 255, 0.1); color: #FFFFFF; border: none; border-radius: 8px; padding: 8px 15px;}}
            QPushButton:hover {{background: rgba(255, 255, 255, 0.2);}}
        """)
        browse_button.clicked.connect(self.select_file)
        file_layout.addWidget(browse_button)
        control_layout.addWidget(file_tile)

        analyze_tile = QFrame()
        analyze_tile.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_COLOR}, stop:1 {HOVER_COLOR}); border-radius: 12px; padding: 10px;")
        analyze_layout = QHBoxLayout(analyze_tile)
        analyze_icon = QLabel("🔍")
        analyze_icon.setFont(QFont("Arial", 20))
        analyze_icon.setStyleSheet(f"color: #FFFFFF; padding: 5px;")
        analyze_layout.addWidget(analyze_icon)

        analyze_label = QLabel("Analyze App")
        analyze_label.setFont(QFont("Arial", 14, QFont.Weight.Medium))
        analyze_label.setStyleSheet(f"color: #FFFFFF;")
        analyze_layout.addWidget(analyze_label)
        analyze_layout.addStretch()

        self.analyze_button = QPushButton("Start")
        self.analyze_button.setFont(QFont("Arial", 12, QFont.Weight.Medium))
        self.analyze_button.setStyleSheet(f"""
            QPushButton {{background: rgba(255, 255, 255, 0.1); color: #FFFFFF; border: none; border-radius: 8px; padding: 8px 15px;}}
            QPushButton:hover {{background: rgba(255, 255, 255, 0.2);}}
            QPushButton:disabled {{background: rgba(255, 255, 255, 0.05); color: #757575;}}
        """)
        self.analyze_button.clicked.connect(self.analyze_file)
        self.analyze_button.setEnabled(False)
        analyze_layout.addWidget(self.analyze_button)
        control_layout.addWidget(analyze_tile)

        reset_tile = QFrame()
        reset_tile.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_COLOR}, stop:1 {HOVER_COLOR}); border-radius: 12px; padding: 10px;")
        reset_layout = QHBoxLayout(reset_tile)
        reset_icon = QLabel("🔄")
        reset_icon.setFont(QFont("Arial", 20))
        reset_icon.setStyleSheet(f"color: #FFFFFF; padding: 5px;")
        reset_layout.addWidget(reset_icon)

        reset_label = QLabel("Reset Analysis")
        reset_label.setFont(QFont("Arial", 14, QFont.Weight.Medium))
        reset_label.setStyleSheet(f"color: #FFFFFF;")
        reset_layout.addWidget(reset_label)
        reset_layout.addStretch()

        self.reset_button = QPushButton("Reset")
        self.reset_button.setFont(QFont("Arial", 12, QFont.Weight.Medium))
        self.reset_button.setStyleSheet(f"""
            QPushButton {{background: rgba(255, 255, 255, 0.1); color: #FFFFFF; border: none; border-radius: 8px; padding: 8px 15px;}}
            QPushButton:hover {{background: rgba(255, 255, 255, 0.2);}}
        """)
        self.reset_button.clicked.connect(self.reset_analysis)
        reset_layout.addWidget(self.reset_button)
        control_layout.addWidget(reset_tile)
        content_layout.addWidget(control_frame)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{background: {CARD_COLOR}; border-radius: 8px; border: 1px solid {ACCENT_COLOR}; text-align: center; color: {TEXT_COLOR}; font-family: 'Arial'; font-size: 12px; padding: 2px;}}
            QProgressBar::chunk {{background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_COLOR}, stop:1 {HOVER_COLOR}); border-radius: 6px;}}
        """)
        content_layout.addWidget(self.progress_bar)

        # Scanning log
        self.scan_log = QTextEdit()
        self.scan_log.setFont(QFont("Arial", 12))
        self.scan_log.setReadOnly(True)
        self.scan_log.setStyleSheet(f"background: {CARD_COLOR}; border-radius: 12px; padding: 15px; color: {TEXT_COLOR}; border: 1px solid {ACCENT_COLOR};")
        self.scan_log.setVisible(False)
        content_layout.addWidget(self.scan_log)

        # Results frame
        self.results_frame = QFrame()
        self.results_frame.setStyleSheet(f"background: {CARD_COLOR}; border-radius: 15px; border: 1px solid {ACCENT_COLOR};")
        self.results_frame.setGraphicsEffect(shadow)
        results_layout = QVBoxLayout(self.results_frame)
        results_layout.setContentsMargins(20, 20, 20, 20)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{background: {CARD_COLOR}; border: 1px solid {ACCENT_COLOR}; border-radius: 12px;}}
            QTabBar::tab {{background: {CARD_COLOR}; color: {TEXT_COLOR}; padding: 10px 20px; border-top-left-radius: 10px; border-top-right-radius: 10px; font-family: 'Arial'; font-size: 12px;}}
            QTabBar::tab:selected {{background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_COLOR}, stop:1 {HOVER_COLOR}); color: #FFFFFF;}}
            QTabBar::tab:!selected {{background: {CARD_COLOR};}}
        """)

        self.summary_tab = QTextEdit()
        self.summary_tab.setFont(QFont("Arial", 12))
        self.summary_tab.setReadOnly(True)
        self.summary_tab.setStyleSheet(f"background: {BACKGROUND_COLOR}; border-radius: 10px; padding: 15px; color: {TEXT_COLOR}; border: none;")
        self.tabs.addTab(self.summary_tab, "Results")

        self.detailed_tab = QTextEdit()
        self.detailed_tab.setFont(QFont("Arial", 12))
        self.detailed_tab.setReadOnly(True)
        self.detailed_tab.setStyleSheet(f"background: {BACKGROUND_COLOR}; border-radius: 10px; padding: 15px; color: {TEXT_COLOR}; border: none;")
        self.tabs.addTab(self.detailed_tab, "Details")

        scroll = QScrollArea()
        scroll.setWidget(self.tabs)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{background: transparent; border: none;}}
            QScrollBar:vertical {{background: {CARD_COLOR}; width: 10px; border-radius: 5px;}}
            QScrollBar::handle:vertical {{background: {ACCENT_COLOR}; border-radius: 5px;}}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{background: none;}}
        """)
        results_layout.addWidget(scroll)
        content_layout.addWidget(self.results_frame, stretch=3)
        layout.addWidget(content_widget, stretch=3)

    def show_how_to_use(self):
        how_to_dialog = QDialog(self)
        how_to_dialog.setWindowTitle("How to Use CipherWraith")
        how_to_dialog.setGeometry(300, 300, 450, 350)
        how_to_dialog.setStyleSheet(f"background: {CARD_COLOR}; border-radius: 15px;")
        layout = QVBoxLayout(how_to_dialog)
        layout.setContentsMargins(20, 20, 20, 20)

        text = QTextBrowser()
        text.setFont(QFont("Arial", 12))
        text.setStyleSheet(f"background: {BACKGROUND_COLOR}; color: {TEXT_COLOR}; border: none; padding: 15px; border-radius: 10px;")
        text.setHtml("""
            <h2 style='color: #BB86FC;'>How to Use CipherWraith</h2>
            <ol>
                <li><b>Select File:</b> Click "Browse" to pick an APK, XAPK, APKM, or IPA file.</li>
                <li><b>Analyze:</b> Hit "Start" to scan the app for security issues.</li>
                <li><b>View Results:</b> Check the "Results" tab for a summary or "Details" for the full report.</li>
                <li><b>Export/Share:</b> Use "Export PDF," "Share," or "Email" to save or send findings.</li>
                <li><b>Reset:</b> Click "Reset" to clear and start over.</li>
            </ol>
        """)
        layout.addWidget(text)
        how_to_dialog.exec()

    def export_pdf(self):
        if not self.summary_tab.toPlainText():
            QMessageBox.warning(self, "Error", "No analysis results to export!")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF Files (*.pdf)")
        if file_path:
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            results = self.summary_tab.toHtml().replace('<br>', '\n').replace('<b>', '').replace('</b>', '')
            for line in results.split('\n'):
                if '<h3' in line:
                    story.append(Paragraph(line.replace('<h3', '').replace('</h3>', '').strip(), styles['Heading1']))
                elif '<li' in line:
                    story.append(Paragraph(f"• {line.replace('<li', '').replace('</li>', '').strip()}", styles['BodyText']))
                else:
                    story.append(Paragraph(line.strip(), styles['BodyText']))
                story.append(Spacer(1, 12))
            doc.build(story)
            QMessageBox.information(self, "Success", f"Results exported to {file_path}")

    def share_results(self):
        if not self.summary_tab.toPlainText():
            QMessageBox.warning(self, "Error", "No analysis results to share!")
            return
        results = self.summary_tab.toPlainText()
        if platform.system() == "Windows":
            subprocess.run(['clip'], input=results.encode('utf-8'), check=True)
        elif platform.system() == "Darwin":
            subprocess.run(['pbcopy'], input=results.encode('utf-8'), check=True)
        else:
            try:
                subprocess.run(['xclip', '-selection', 'clipboard'], input=results.encode('utf-8'), check=True)
            except FileNotFoundError:
                QMessageBox.warning(self, "Error", "xclip not found.")
        QMessageBox.information(self, "Success", "Results copied to clipboard.")

    def email_results(self):
        if not self.summary_tab.toPlainText():
            QMessageBox.warning(self, "Error", "No analysis results to email!")
            return
        subject = "CipherWraith Analyzer Results"
        body = self.summary_tab.toPlainText().replace('\n', '%0D%0A')
        webbrowser.open(f"mailto:?subject={subject}&body={body}")

    def select_file(self):
        file_filter = "App Files (*" + " *".join(APK_EXTENSIONS) + " *.ipa);;All Files (*)"
        file_path, _ = QFileDialog.getOpenFileName(self, "Select App File", "", file_filter)
        if file_path:
            self.file_path = file_path
            self.file_label.setText(f"Selected: {os.path.basename(file_path)}")
            self.analyze_button.setEnabled(True)
            self.summary_tab.clear()
            self.detailed_tab.clear()
            self.scan_log.clear()
            self.scan_log.setVisible(False)

    def reset_analysis(self):
        self.file_label.setText("Select an App File")
        self.analyze_button.setEnabled(False)
        self.summary_tab.clear()
        self.detailed_tab.clear()
        self.scan_log.clear()
        self.scan_log.setVisible(False)
        self.static_status.setText("Ready")

    def analyze_file(self):
        if not hasattr(self, 'file_path'):
            QMessageBox.warning(self, "Error", "Please select a file first!")
            return
        file_ext = os.path.splitext(self.file_path)[1].lower()[1:]
        self.summary_tab.clear()
        self.detailed_tab.clear()
        self.scan_log.clear()
        self.scan_log.setVisible(True)
        self.results_frame.setVisible(False)
        self.analyze_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.static_status.setText("Analyzing...")

        self.thread = AnalysisThread(self.file_path, file_ext)
        self.thread.update_signal.connect(self.update_scan_log)
        self.thread.finished_signal.connect(self.display_results)
        self.thread.start()

    def update_scan_log(self, message):
        self.scan_log.append(f"<i>{message}</i>")
        current_value = self.progress_bar.value()
        self.progress_bar.setValue(min(current_value + 10, 90))

    def display_results(self, summarized_vulns, full_vulns):
        self.progress_bar.setValue(100)
        self.progress_bar.setVisible(False)
        self.scan_log.setVisible(False)
        self.results_frame.setVisible(True)
        self.analyze_button.setEnabled(True)
        self.static_status.setText("Complete")
        self.full_vulnerabilities = full_vulns

        # Summary Tab
        self.summary_tab.append("<hr><h3 style='color: #BB86FC;'>Analysis Results</h3>")
        if summarized_vulns:
            self.summary_tab.append("<ul style='margin-left: 20px;'>")
            for vuln in summarized_vulns:
                self.summary_tab.append(f"<li style='color: {ERROR_COLOR};'>{vuln}</li>")
            if not any("insufficient key length" in v.lower() for v in full_vulns):
                self.summary_tab.append(f"<li style='color: {SUCCESS_COLOR};'>No Insufficient Key Lengths detected</li>")
            
        else:
            self.summary_tab.append("<p style='color: #03DAC6;'>✔ No issues found.</p>")

        # Detailed Tab
        self.detailed_tab.append("<hr><h3 style='color: #BB86FC;'>Detailed Analysis Results</h3>")
        if full_vulns:
            weak_algo_vulns = [v for v in full_vulns if "weak algorithm" in v.lower()]
            insuf_key_vulns = [v for v in full_vulns if "insufficient key length" in v.lower()]
            other_vulns = [v for v in full_vulns if v not in weak_algo_vulns and v not in insuf_key_vulns]

            if weak_algo_vulns:
                self.detailed_tab.append("<h4 style='color: #FF9800;'><b>Weak Encryption Algorithms</b></h4>")
                self.detailed_tab.append("<ul style='margin-left: 20px;'>")
                for vuln in weak_algo_vulns:
                    self.detailed_tab.append(f"<li style='color: {ERROR_COLOR};'>{vuln}</li>")
                
            else:
                self.detailed_tab.append("<p style='color: #03DAC6;'>✔ No weak encryption algorithms found.</p>")

            if insuf_key_vulns:
                self.detailed_tab.append("<h4 style='color: #E91E63;'><b>Insufficient Key Length</b></h4>")
                self.detailed_tab.append("<ul style='margin-left: 20px;'>")
                for vuln in insuf_key_vulns:
                    self.detailed_tab.append(f"<li style='color: {ERROR_COLOR};'>{vuln}</li>")
                
            else:
                self.detailed_tab.append("<p style='color: #03DAC6;'>✔ No insufficient key lengths found.</p>")

            if other_vulns:
                self.detailed_tab.append("<h4 style='color: #FF5722;'><b>Other Issues</b></h4>")
                self.detailed_tab.append("<ul style='margin-left: 20px;'>")
                for vuln in other_vulns:
                    self.detailed_tab.append(f"<li style='color: {ERROR_COLOR};'>{vuln}</li>")
                

        # Potential Risks
        self.summary_tab.append("<h3 style='color: #BB86FC;'>Potential Risks</h3>")
        combined_vulns = " ".join(full_vulns).lower()
        risks = []
        if "cleartext" in combined_vulns or "insecure" in combined_vulns:
            risks.append("Scenario #1: Man-in-the-Middle (MitM) Attacks - An attacker intercepts communication.")
        if "weak" in combined_vulns or "insufficient" in combined_vulns:
            risks.append("Scenario #2: Brute-Force Attacks - Weak cryptography enables cracking.")
        if "hardcoded" in combined_vulns or "key" in combined_vulns:
            risks.append("Scenario #4: Key Management Vulnerabilities - Exposed keys mean leaks.")
        if risks:
            self.summary_tab.append("<ul style='margin-left: 20px;'>")
            for risk in risks:
                self.summary_tab.append(f"<li style='color: {ERROR_COLOR};'>{risk}</li>")
            
            self.summary_tab.append("<p style='color: #E0E0E0;'>Recommendation: Avoid sensitive data usage or contact the developer.</p>")
        else:
            self.summary_tab.append("<p style='color: #03DAC6;'>✔ No significant risks detected.</p>")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CipherWraith()
    window.show()
    sys.exit(app.exec())