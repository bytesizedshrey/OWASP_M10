import sys
import os
import re
import zipfile
import subprocess
import tempfile
import threading
import json
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QPushButton, QFileDialog, QTextEdit, QTabWidget, 
                           QProgressBar, QComboBox, QMessageBox, QGroupBox, QScrollArea)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon


class CryptoScannerThread(QThread):
    progress_update = pyqtSignal(int)
    log_update = pyqtSignal(str)
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, file_path, app_type):
        super().__init__()
        self.file_path = file_path
        self.app_type = app_type  # 'apk' or 'ipa'
        self.temp_dir = None
        
    def run(self):
        results = {
            "weak_algorithms": [],
            "key_management_issues": [],
            "transport_layer_issues": [],
            "hash_function_issues": [],
            "severity_score": 0
        }
        
        self.log_update.emit(f"Starting analysis of {os.path.basename(self.file_path)}")
        self.progress_update.emit(10)
        
        # Extract the file for static analysis
        self.temp_dir = tempfile.mkdtemp()
        self.log_update.emit(f"Extracting {self.app_type.upper()} file to {self.temp_dir}")
        
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            self.log_update.emit("Extraction completed successfully")
        except Exception as e:
            self.log_update.emit(f"Error extracting file: {str(e)}")
            return
        
        self.progress_update.emit(30)
        
        # Perform static analysis
        if self.app_type == 'apk':
            results = self.analyze_apk(results)
        else:  # ipa
            results = self.analyze_ipa(results)
        
        self.progress_update.emit(100)
        self.scan_complete.emit(results)
        
    def analyze_apk(self, results):
        # Look for weak crypto algorithms in decompiled code
        self.log_update.emit("Performing static analysis for weak cryptographic algorithms...")
        
        # Search for Java files and smali files
        java_files = []
        smali_files = []
        dex_files = []
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(".java"):
                    java_files.append(os.path.join(root, file))
                elif file.endswith(".smali"):
                    smali_files.append(os.path.join(root, file))
                elif file.endswith(".dex"):
                    dex_files.append(os.path.join(root, file))
        
        self.log_update.emit(f"Found {len(java_files)} Java files, {len(smali_files)} Smali files, and {len(dex_files)} DEX files")
        self.progress_update.emit(40)
        
        # Check for weak crypto patterns
        weak_crypto_patterns = [
            (r"DES", "Weak encryption algorithm (DES)"),
            (r"RC4", "Weak encryption algorithm (RC4)"),
            (r"MD5", "Weak hash function (MD5)"),
            (r"SHA-1|SHA1", "Weak hash function (SHA-1)"),
            (r"ECB mode", "Weak encryption mode (ECB)"),
            (r"KeyGenerator.getInstance\([\"']DES[\"']", "Using DES key generation"),
            (r"KeyGenerator.getInstance\([\"']AES[\"'].*keySize.*64", "Insufficient AES key size"),
            (r"SecureRandom.setSeed\(System.currentTimeMillis", "Predictable seed for SecureRandom"),
            (r"javax.crypto.Cipher.getInstance\([\"']AES/ECB", "Using ECB mode for AES"),
            (r"getBytes\(\).length", "Using string length as key size")
        ]
        
        # Check for insecure key management patterns
        key_management_patterns = [
            (r"String\s+.*[pP]assword\s*=\s*[\"'].*[\"']", "Hardcoded password/key"),
            (r"String\s+.*[kK]ey\s*=\s*[\"'].*[\"']", "Hardcoded encryption key"),
            (r"getSharedPreferences\(.*MODE_PRIVATE", "Possibly storing keys in SharedPreferences"),
            (r"SQLiteDatabase", "Possibly storing keys in SQLite without encryption"),
            (r"putString\(.*[pP]assword", "Storing password/key in preferences"),
            (r"putString\(.*[kK]ey", "Storing encryption key in preferences"),
            (r"getWritableDatabase\(\)", "Possible unencrypted database usage")
        ]
        
        # Check for transport layer issues
        transport_patterns = [
            (r"javax.net.ssl.TrustManager.*checkServerTrusted", "Custom TrustManager may bypass certificate validation"),
            (r"X509TrustManager.*checkServerTrusted.*return", "Certificate validation may be bypassed"),
            (r"http://", "Using plain HTTP instead of HTTPS"),
            (r"setHostnameVerifier.*ALLOW_ALL", "Allowing all hostnames in SSL verification"),
            (r"allowAllSSL", "Disabling SSL verification"),
            (r"setSSLSocketFactory\(.*\)", "Custom SSL Socket Factory may disable proper verification")
        ]
        
        # Function to check a file against multiple patterns
        def check_file_for_patterns(file_path, patterns, issue_type):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            issue = {
                                "description": description,
                                "file": os.path.relpath(file_path, self.temp_dir),
                                "line": line_num,
                                "context": match.group(0)[:100] if match else ""
                            }
                            if issue_type == "weak_algorithms":
                                results["weak_algorithms"].append(issue)
                            elif issue_type == "key_management":
                                results["key_management_issues"].append(issue)
                            elif issue_type == "transport_layer":
                                results["transport_layer_issues"].append(issue)
                            
                            self.log_update.emit(f"Found issue: {description} in {os.path.basename(file_path)} at line {line_num}")
            except Exception as e:
                self.log_update.emit(f"Error analyzing file {file_path}: {str(e)}")
        
        # Analyze Java files
        file_count = len(java_files) + len(smali_files)
        current_file = 0
        
        for file in java_files:
            check_file_for_patterns(file, weak_crypto_patterns, "weak_algorithms")
            check_file_for_patterns(file, key_management_patterns, "key_management")
            check_file_for_patterns(file, transport_patterns, "transport_layer")
            current_file += 1
            self.progress_update.emit(40 + int((current_file / file_count) * 30))
        
        # Analyze smali files
        for file in smali_files:
            check_file_for_patterns(file, weak_crypto_patterns, "weak_algorithms")
            check_file_for_patterns(file, key_management_patterns, "key_management")
            check_file_for_patterns(file, transport_patterns, "transport_layer")
            current_file += 1
            self.progress_update.emit(40 + int((current_file / file_count) * 30))
        
        # Check manifest for network security configuration
        manifest_path = os.path.join(self.temp_dir, "AndroidManifest.xml")
        network_security_config = False
        cleartext_traffic_allowed = True
        
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    manifest_content = f.read()
                    if "android:networkSecurityConfig" in manifest_content:
                        network_security_config = True
                    if "android:usesCleartextTraffic=\"false\"" in manifest_content:
                        cleartext_traffic_allowed = False
            except Exception as e:
                self.log_update.emit(f"Error analyzing manifest: {str(e)}")
        
        if not network_security_config:
            results["transport_layer_issues"].append({
                "description": "No network security configuration found",
                "file": "AndroidManifest.xml",
                "line": 0,
                "context": "Missing android:networkSecurityConfig attribute"
            })
            self.log_update.emit("Issue: No network security configuration found")
        
        if cleartext_traffic_allowed:
            results["transport_layer_issues"].append({
                "description": "Cleartext traffic allowed",
                "file": "AndroidManifest.xml",
                "line": 0,
                "context": "Missing android:usesCleartextTraffic=\"false\" attribute"
            })
            self.log_update.emit("Issue: Cleartext traffic allowed")
        
        # Calculate severity score
        severity = 0
        severity += len(results["weak_algorithms"]) * 5
        severity += len(results["key_management_issues"]) * 8
        severity += len(results["transport_layer_issues"]) * 7
        
        # Cap severity at 100
        results["severity_score"] = min(severity, 100)
        
        self.log_update.emit(f"Analysis complete. Severity score: {results['severity_score']}")
        
        return results
    
    def analyze_ipa(self, results):
        # IPA static analysis
        self.log_update.emit("Performing static analysis for IPA file...")
        
        # Search for relevant files
        objective_c_files = []
        swift_files = []
        plist_files = []
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(".m") or file.endswith(".h"):
                    objective_c_files.append(os.path.join(root, file))
                elif file.endswith(".swift"):
                    swift_files.append(os.path.join(root, file))
                elif file.endswith(".plist"):
                    plist_files.append(os.path.join(root, file))
        
        self.log_update.emit(f"Found {len(objective_c_files)} Objective-C files, {len(swift_files)} Swift files, and {len(plist_files)} plist files")
        self.progress_update.emit(40)
        
        # Check for weak crypto patterns
        weak_crypto_patterns = [
            (r"CommonCrypto.*kCCAlgorithmDES", "Weak encryption algorithm (DES)"),
            (r"CommonCrypto.*kCCAlgorithm3DES", "Weak encryption algorithm (3DES)"),
            (r"CommonCrypto.*kCCAlgorithmRC4", "Weak encryption algorithm (RC4)"),
            (r"CC_MD5", "Weak hash function (MD5)"),
            (r"CC_SHA1", "Weak hash function (SHA-1)"),
            (r"kCCOptionECBMode", "Weak encryption mode (ECB)"),
            (r"SecRandomCopyBytes.*[0-9]", "Potentially insufficient random bytes"),
            (r"kSecAttrKeyType.*kSecAttrKeyTypeRSA.*512", "Insufficient RSA key size"),
            (r"kSecAttrKeyType.*kSecAttrKeyTypeRSA.*1024", "Insufficient RSA key size")
        ]
        
        # Check for insecure key management patterns
        key_management_patterns = [
            (r"NSUserDefaults", "Possibly storing keys in UserDefaults"),
            (r"@\"[^\"]*password[^\"]*\"\s*:\s*@\"", "Hardcoded password/key"),
            (r"@\"[^\"]*key[^\"]*\"\s*:\s*@\"", "Hardcoded encryption key"),
            (r"\\blet\\s+.*[pP]assword\\s*=\\s*\".*\"", "Hardcoded password in Swift"),
            (r"\\blet\\s+.*[kK]ey\\s*=\\s*\".*\"", "Hardcoded key in Swift"),
            (r"NSData.*dataUsingEncoding", "Possibly insecure conversion of string to data"),
            (r"setObject:forKey:.*[pP]assword", "Storing password in UserDefaults"),
            (r"setObject:forKey:.*[kK]ey", "Storing encryption key in UserDefaults")
        ]
        
        # Check for transport layer issues
        transport_patterns = [
            (r"NSURLConnection.*evaluateServerTrust", "Custom certificate validation logic"),
            (r"allowsInvalidSSLCertificate", "Allowing invalid SSL certificates"),
            (r"canAuthenticateAgainstProtectionSpace", "Custom authentication against protection space"),
            (r"http://", "Using plain HTTP instead of HTTPS"),
            (r"continueWithoutCredentialForAuthenticationChallenge", "Continuing without proper authentication"),
            (r"setAllowsAnyHTTPSCertificate", "Allowing any HTTPS certificate"),
            (r"setValidatesSecureCertificate:\\s*NO", "Disabling secure certificate validation")
        ]
        
        # Function to check a file against multiple patterns
        def check_file_for_patterns(file_path, patterns, issue_type):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern, description in patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            issue = {
                                "description": description,
                                "file": os.path.relpath(file_path, self.temp_dir),
                                "line": line_num,
                                "context": match.group(0)[:100] if match else ""
                            }
                            if issue_type == "weak_algorithms":
                                results["weak_algorithms"].append(issue)
                            elif issue_type == "key_management":
                                results["key_management_issues"].append(issue)
                            elif issue_type == "transport_layer":
                                results["transport_layer_issues"].append(issue)
                            
                            self.log_update.emit(f"Found issue: {description} in {os.path.basename(file_path)} at line {line_num}")
            except Exception as e:
                self.log_update.emit(f"Error analyzing file {file_path}: {str(e)}")
        
        # Analyze objective-c and swift files
        file_count = len(objective_c_files) + len(swift_files)
        current_file = 0
        
        for file in objective_c_files:
            check_file_for_patterns(file, weak_crypto_patterns, "weak_algorithms")
            check_file_for_patterns(file, key_management_patterns, "key_management")
            check_file_for_patterns(file, transport_patterns, "transport_layer")
            current_file += 1
            self.progress_update.emit(40 + int((current_file / file_count) * 30))
        
        for file in swift_files:
            check_file_for_patterns(file, weak_crypto_patterns, "weak_algorithms")
            check_file_for_patterns(file, key_management_patterns, "key_management")
            check_file_for_patterns(file, transport_patterns, "transport_layer")
            current_file += 1
            self.progress_update.emit(40 + int((current_file / file_count) * 30))
        
        # Check Info.plist for App Transport Security settings
        for plist_file in plist_files:
            if os.path.basename(plist_file) == "Info.plist":
                try:
                    with open(plist_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if "NSAllowsArbitraryLoads" in content and "<true/>" in content[content.find("NSAllowsArbitraryLoads"):content.find("</key>", content.find("NSAllowsArbitraryLoads")) + 100]:
                            results["transport_layer_issues"].append({
                                "description": "App Transport Security is disabled",
                                "file": os.path.relpath(plist_file, self.temp_dir),
                                "line": 0,
                                "context": "NSAllowsArbitraryLoads is set to true"
                            })
                            self.log_update.emit("Issue: App Transport Security is disabled")
                except Exception as e:
                    self.log_update.emit(f"Error analyzing plist file {plist_file}: {str(e)}")
        
        # Calculate severity score
        severity = 0
        severity += len(results["weak_algorithms"]) * 5
        severity += len(results["key_management_issues"]) * 8
        severity += len(results["transport_layer_issues"]) * 7
        
        # Cap severity at 100
        results["severity_score"] = min(severity, 100)
        
        self.log_update.emit(f"Analysis complete. Severity score: {results['severity_score']}")
        
        return results


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.scanner_thread = None
        
    def initUI(self):
        self.setWindowTitle("Mobile App Cryptography Analyzer")
        self.setGeometry(100, 100, 1000, 700)
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # File selection area
        file_group = QGroupBox("File Selection")
        file_layout = QHBoxLayout()
        file_group.setLayout(file_layout)
        
        self.file_path_label = QLabel("No file selected")
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path_label)
        file_layout.addWidget(self.browse_button)
        
        # App type selection
        self.app_type_combo = QComboBox()
        self.app_type_combo.addItems(["APK (Android)", "IPA (iOS)"])
        file_layout.addWidget(QLabel("App Type:"))
        file_layout.addWidget(self.app_type_combo)
        
        # Scan button
        self.scan_button = QPushButton("Start Analysis")
        self.scan_button.clicked.connect(self.start_scan)
        file_layout.addWidget(self.scan_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        
        # Tab widget for results
        self.tab_widget = QTabWidget()
        
        # Logs tab
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.tab_widget.addTab(self.log_text, "Logs")
        
        # Results tabs
        self.weak_algorithms_tab = QWidget()
        self.key_management_tab = QWidget()
        self.transport_layer_tab = QWidget()
        self.vulnerabilities_tab = QWidget()
        
        self.tab_widget.addTab(self.weak_algorithms_tab, "Weak Algorithms")
        self.tab_widget.addTab(self.key_management_tab, "Key Management")
        self.tab_widget.addTab(self.transport_layer_tab, "Transport Layer")
        self.tab_widget.addTab(self.vulnerabilities_tab, "Attack Scenarios")
        
        # Setup tabs
        self.setup_weak_algorithms_tab()
        self.setup_key_management_tab()
        self.setup_transport_layer_tab()
        self.setup_vulnerabilities_tab()
        
        # Add widgets to main layout
        main_layout.addWidget(file_group)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.tab_widget, stretch=1)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Show the window
        self.show()
    
    def setup_weak_algorithms_tab(self):
        layout = QVBoxLayout()
        
        self.weak_algorithms_text = QTextEdit()
        self.weak_algorithms_text.setReadOnly(True)
        
        layout.addWidget(self.weak_algorithms_text)
        self.weak_algorithms_tab.setLayout(layout)
    
    def setup_key_management_tab(self):
        layout = QVBoxLayout()
        
        self.key_management_text = QTextEdit()
        self.key_management_text.setReadOnly(True)
        
        layout.addWidget(self.key_management_text)
        self.key_management_tab.setLayout(layout)
    
    def setup_transport_layer_tab(self):
        layout = QVBoxLayout()
        
        self.transport_layer_text = QTextEdit()
        self.transport_layer_text.setReadOnly(True)
        
        layout.addWidget(self.transport_layer_text)
        self.transport_layer_tab.setLayout(layout)
    
    def setup_vulnerabilities_tab(self):
        layout = QVBoxLayout()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        vulns_widget = QWidget()
        vulns_layout = QVBoxLayout()
        vulns_widget.setLayout(vulns_layout)
        
        # Add attack scenarios from the document
        scenarios = [
            {
                "title": "Scenario #1: Man-in-the-Middle (MitM) Attacks",
                "description": "An attacker intercepts the communication between the mobile application and the server. Weak cryptography can enable attackers to decrypt the intercepted data, modify it, and re-encrypt it before forwarding it to the intended recipient. This can lead to unauthorized access, data manipulation, or the injection of malicious content."
            },
            {
                "title": "Scenario #2: Brute-Force Attacks",
                "description": "Attackers systematically try various combinations of keys until they find the correct one to decrypt the data. Weak cryptography can shorten the time required for such attacks, potentially exposing sensitive information."
            },
            {
                "title": "Scenario #3: Cryptographic Downgrade Attacks",
                "description": "Mobile applications may support multiple encryption protocols or algorithms to establish secure connections. If weak cryptography is allowed as a fallback option, attackers can exploit this weakness and force the application to use weak encryption. As a result, they can decrypt the intercepted data more easily and launch subsequent attacks."
            },
            {
                "title": "Scenario #4: Key Management Vulnerabilities",
                "description": "Weak key management practices can undermine the security of the cryptographic systems used in mobile applications. For example, if encryption keys are stored insecurely or are easily guessable, attackers can gain unauthorized access to the keys and decrypt the encrypted data. This can result in data breaches and privacy violations."
            },
            {
                "title": "Scenario #5: Crypto Implementation Flaws",
                "description": "Weak cryptography can also stem from implementation flaws in the mobile application itself. These flaws may include incorrect usage of cryptographic libraries, insecure key generation, improper random number generation, or insecure handling of encryption-related functions. Attackers can exploit these flaws to bypass or weaken the encryption protections."
            }
        ]
        
        for scenario in scenarios:
            group = QGroupBox(scenario["title"])
            group_layout = QVBoxLayout()
            
            desc_label = QLabel(scenario["description"])
            desc_label.setWordWrap(True)
            
            risk_status = QLabel("Risk Status: Not analyzed yet")
            risk_status.setProperty("scenario", scenario["title"])
            
            group_layout.addWidget(desc_label)
            group_layout.addWidget(risk_status)
            
            group.setLayout(group_layout)
            vulns_layout.addWidget(group)
        
        # Add a spacer to push everything up
        vulns_layout.addStretch()
        
        scroll.setWidget(vulns_widget)
        layout.addWidget(scroll)
        self.vulnerabilities_tab.setLayout(layout)
    """ 
    def browse_file(self):
        options = QFileDialog.Option()
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Mobile App File",
            "",
            "Mobile App Files (*.apk *.ipa);;All Files (*)",
            options=options
        )
    """
    def browse_file(self):
        options = QFileDialog.Option(0)  # Default empty option
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Mobile App File",
            "",
            "Mobile App Files (*.apk *.ipa);;All Files (*)",
            options=options
        )
        if file_path:
            self.file_path_label.setText(file_path)
        
        
        if file_path:
            self.file_path_label.setText(file_path)
            
            # Auto-select app type based on extension
            if file_path.lower().endswith('.apk'):
                self.app_type_combo.setCurrentIndex(0)  # APK
            elif file_path.lower().endswith('.ipa'):
                self.app_type_combo.setCurrentIndex(1)  # IPA
    
    def start_scan(self):
        file_path = self.file_path_label.text()
        
        if file_path == "No file selected":
            QMessageBox.warning(self, "Warning", "Please select a file first!")
            return
        
        # Get app type
        app_type = "apk" if self.app_type_combo.currentIndex() == 0 else "ipa"
        
        # Disable the scan button during scan
        self.scan_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.progress_bar.setValue(0)
        
        # Clear previous results
        self.log_text.clear()
        self.weak_algorithms_text.clear()
        self.key_management_text.clear()
        self.transport_layer_text.clear()
        
        # Reset vulnerability risk status
        for i in range(self.vulnerabilities_tab.layout().count()):
            widget = self.vulnerabilities_tab.layout().itemAt(i).widget()
            if isinstance(widget, QScrollArea):
                scroll_widget = widget.widget()
                for j in range(scroll_widget.layout().count() - 1):  # -1 to exclude the spacer
                    group_box = scroll_widget.layout().itemAt(j).widget()
                    if isinstance(group_box, QGroupBox):
                        for k in range(group_box.layout().count()):
                            risk_widget = group_box.layout().itemAt(k).widget()
                            if isinstance(risk_widget, QLabel) and risk_widget.property("scenario"):
                                risk_widget.setText("Risk Status: Not analyzed yet")
        
        # Start the scanner thread
        self.scanner_thread = CryptoScannerThread(file_path, app_type)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.log_update.connect(self.update_log)
        self.scanner_thread.scan_complete.connect(self.show_results)
        self.scanner_thread.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_log(self, message):
        self.log_text.append(message)
        # Auto-scroll to bottom
        cursor = self.log_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_text.setTextCursor(cursor)
    
    def show_results(self, results):
        # Re-enable buttons
        self.scan_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        
        # Update status bar
        self.statusBar().showMessage(f"Analysis complete. Severity score: {results['severity_score']}/100")
        
        # Update weak algorithms tab
        if results["weak_algorithms"]:
            self.weak_algorithms_text.append("<h2>Weak Cryptography Algorithms Found</h2>")
            for issue in results["weak_algorithms"]:
                self.weak_algorithms_text.append(f"<p><b>{issue['description']}</b><br>")
                self.weak_algorithms_text.append(f"File: {issue['file']}<br>")
                self.weak_algorithms_text.append(f"Line: {issue['line']}<br>")
                self.weak_algorithms_text.append(f"Context: <code>{issue['context']}</code></p>")
                self.weak_algorithms_text.append("<hr>")
        else:
            self.weak_algorithms_text.append("<h2>No weak cryptography algorithms found</h2>")
        
        # Update key management tab
        if results["key_management_issues"]:
            self.key_management_text.append("<h2>Key Management Issues Found</h2>")
            for issue in results["key_management_issues"]:
                self.key_management_text.append(f"<p><b>{issue['description']}</b><br>")
                self.key_management_text.append(f"File: {issue['file']}<br>")
                self.key_management_text.append(f"Line: {issue['line']}<br>")
                self.key_management_text.append(f"Context: <code>{issue['context']}</code></p>")
                self.key_management_text.append("<hr>")
        else:
            self.key_management_text.append("<h2>No key management issues found</h2>")
        
        # Update transport layer tab
        if results["transport_layer_issues"]:
            self.transport_layer_text.append("<h2>Transport Layer Security Issues Found</h2>")
            for issue in results["transport_layer_issues"]:
                self.transport_layer_text.append(f"<p><b>{issue['description']}</b><br>")
                self.transport_layer_text.append(f"File: {issue['file']}<br>")
                self.transport_layer_text.append(f"Line: {issue['line']}<br>")
                self.transport_layer_text.append(f"Context: <code>{issue['context']}</code></p>")
                self.transport_layer_text.append("<hr>")
        else:
            self.transport_layer_text.append("<h2>No transport layer security issues found</h2>")

# Update vulnerabilities tab with risk assessment
        for i in range(self.vulnerabilities_tab.layout().count()):
            widget = self.vulnerabilities_tab.layout().itemAt(i).widget()
            if isinstance(widget, QScrollArea):
                scroll_widget = widget.widget()
                for j in range(scroll_widget.layout().count() - 1):  # -1 to exclude the spacer
                    group_box = scroll_widget.layout().itemAt(j).widget()
                    if isinstance(group_box, QGroupBox):
                        scenario_title = group_box.title()
                        risk_level = "Low"
                        description = ""
                        
                        # Determine risk level for each scenario based on findings
                        if "Man-in-the-Middle" in scenario_title:
                            if any("HTTPS" in issue["description"] for issue in results["transport_layer_issues"]):
                                risk_level = "High"
                                description = "High risk due to insecure transport layer configurations detected."
                            elif results["transport_layer_issues"]:
                                risk_level = "Medium"
                                description = "Medium risk due to potential transport layer vulnerabilities."
                            else:
                                description = "Low risk - no clear transport layer vulnerabilities detected."
                                
                        elif "Brute-Force" in scenario_title:
                            if any("weak" in issue["description"].lower() for issue in results["weak_algorithms"]):
                                risk_level = "High" 
                                description = "High risk due to weak encryption algorithms that are vulnerable to brute-force attacks."
                            elif results["weak_algorithms"]:
                                risk_level = "Medium"
                                description = "Medium risk due to potential weaknesses in cryptographic implementations."
                            else:
                                description = "Low risk - no clear weak algorithms detected."
                                
                        elif "Cryptographic Downgrade" in scenario_title:
                            if any("ECB" in issue["description"] or "weak" in issue["description"].lower() for issue in results["weak_algorithms"]):
                                risk_level = "Medium"
                                description = "Medium risk due to the presence of weak algorithms that could be used in downgrade attacks."
                            elif results["transport_layer_issues"]:
                                risk_level = "Medium"
                                description = "Medium risk due to potential transport layer vulnerabilities that could enable downgrade attacks."
                            else:
                                description = "Low risk - no clear indicators of downgrade vulnerabilities."
                                
                        elif "Key Management" in scenario_title:
                            if results["key_management_issues"]:
                                risk_level = "High"
                                description = "High risk due to key management issues detected."
                            else:
                                description = "Low risk - no clear key management issues detected."
                                
                        elif "Crypto Implementation" in scenario_title:
                            if results["weak_algorithms"] or results["key_management_issues"]:
                                risk_level = "High"
                                description = "High risk due to potential implementation flaws in cryptographic functions."
                            else:
                                description = "Low risk - no clear implementation flaws detected."
                        
                        # Color code the risk level
                        color = {
                            "Low": "green",
                            "Medium": "orange",
                            "High": "red"
                        }.get(risk_level, "black")
                        
                        # Find the risk status label and update it
                        for k in range(group_box.layout().count()):
                            risk_widget = group_box.layout().itemAt(k).widget()
                            if isinstance(risk_widget, QLabel) and risk_widget.property("scenario"):
                                risk_widget.setText(f"Risk Status: <span style='color:{color};font-weight:bold;'>{risk_level}</span> - {description}")
                                break
        
        # Show a summary message box
        severity = results["severity_score"]
        if severity > 70:
            severity_text = "Critical"
            severity_color = "red"
        elif severity > 40:
            severity_text = "High"
            severity_color = "orange"
        elif severity > 20:
            severity_text = "Medium"
            severity_color = "yellow"
        else:
            severity_text = "Low"
            severity_color = "green"
        
        message = f"""
        <h2>Scan Complete</h2>
        <p>Overall Severity: <span style='color:{severity_color};font-weight:bold;'>{severity_text}</span> ({severity}/100)</p>
        <p>Found issues:</p>
        <ul>
            <li>Weak Algorithms: {len(results["weak_algorithms"])}</li>
            <li>Key Management Issues: {len(results["key_management_issues"])}</li>
            <li>Transport Layer Issues: {len(results["transport_layer_issues"])}</li>
        </ul>
        <p>Please check the respective tabs for detailed information.</p>
        """
        
        QMessageBox.information(self, "Analysis Results", message)
        
        # Set tab index to the appropriate tab based on findings
        if results["weak_algorithms"]:
            self.tab_widget.setCurrentIndex(1)  # Weak Algorithms tab
        elif results["key_management_issues"]:
            self.tab_widget.setCurrentIndex(2)  # Key Management tab
        elif results["transport_layer_issues"]:
            self.tab_widget.setCurrentIndex(3)  # Transport Layer tab
        else:
            self.tab_widget.setCurrentIndex(4)  # Attack Scenarios tab


def generate_sample_report(results, file_path, app_type):
    """Generate a sample HTML report based on scan results"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mobile App Crypto Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #333; }}
            .critical {{ color: red; }}
            .high {{ color: orange; }}
            .medium {{ color: #DAA520; }}
            .low {{ color: green; }}
            .issue {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }}
            .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Mobile App Cryptography Security Analysis</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>File:</strong> {os.path.basename(file_path)}</p>
            <p><strong>App Type:</strong> {app_type.upper()}</p>
            <p><strong>Analysis Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h3>Severity Score: 
    """
    
    severity = results["severity_score"]
    if severity > 70:
        html += f'<span class="critical">{severity}/100 (Critical)</span>'
    elif severity > 40:
        html += f'<span class="high">{severity}/100 (High)</span>'
    elif severity > 20:
        html += f'<span class="medium">{severity}/100 (Medium)</span>'
    else:
        html += f'<span class="low">{severity}/100 (Low)</span>'
    
    html += f"""
            </h3>
            
            <table>
                <tr>
                    <th>Issue Type</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td>Weak Algorithms</td>
                    <td>{len(results["weak_algorithms"])}</td>
                </tr>
                <tr>
                    <td>Key Management Issues</td>
                    <td>{len(results["key_management_issues"])}</td>
                </tr>
                <tr>
                    <td>Transport Layer Issues</td>
                    <td>{len(results["transport_layer_issues"])}</td>
                </tr>
            </table>
        </div>
        
        <h2>Detailed Findings</h2>
    """
    
    # Weak Algorithms
    if results["weak_algorithms"]:
        html += '<h3>Weak Cryptography Algorithms</h3>'
        for issue in results["weak_algorithms"]:
            html += f"""
            <div class="issue">
                <h4>{issue["description"]}</h4>
                <p><strong>File:</strong> {issue["file"]}</p>
                <p><strong>Line:</strong> {issue["line"]}</p>
                <p><strong>Context:</strong> <code>{issue["context"]}</code></p>
            </div>
            """
    else:
        html += '<h3>Weak Cryptography Algorithms</h3><p>No issues found</p>'
    
    # Key Management
    if results["key_management_issues"]:
        html += '<h3>Key Management Issues</h3>'
        for issue in results["key_management_issues"]:
            html += f"""
            <div class="issue">
                <h4>{issue["description"]}</h4>
                <p><strong>File:</strong> {issue["file"]}</p>
                <p><strong>Line:</strong> {issue["line"]}</p>
                <p><strong>Context:</strong> <code>{issue["context"]}</code></p>
            </div>
            """
    else:
        html += '<h3>Key Management Issues</h3><p>No issues found</p>'
    
    # Transport Layer
    if results["transport_layer_issues"]:
        html += '<h3>Transport Layer Security Issues</h3>'
        for issue in results["transport_layer_issues"]:
            html += f"""
            <div class="issue">
                <h4>{issue["description"]}</h4>
                <p><strong>File:</strong> {issue["file"]}</p>
                <p><strong>Line:</strong> {issue["line"]}</p>
                <p><strong>Context:</strong> <code>{issue["context"]}</code></p>
            </div>
            """
    else:
        html += '<h3>Transport Layer Security Issues</h3><p>No issues found</p>'
    
    # Add attack scenarios
    html += """
        <h2>Attack Scenario Analysis</h2>
        
        <div class="issue">
            <h3>Scenario #1: Man-in-the-Middle (MitM) Attacks</h3>
            <p>An attacker intercepts the communication between the mobile application and the server. Weak cryptography can enable attackers to decrypt the intercepted data, modify it, and re-encrypt it before forwarding it to the intended recipient. This can lead to unauthorized access, data manipulation, or the injection of malicious content.</p>
    """
    
    # Risk assessment for MitM
    if any("HTTPS" in issue["description"] for issue in results["transport_layer_issues"]):
        html += '<p><span class="critical">High Risk</span> - Insecure transport layer configurations detected that could enable MitM attacks.</p>'
    elif results["transport_layer_issues"]:
        html += '<p><span class="high">Medium Risk</span> - Potential transport layer vulnerabilities that might facilitate MitM attacks.</p>'
    else:
        html += '<p><span class="low">Low Risk</span> - No clear transport layer vulnerabilities detected that would enable MitM attacks.</p>'
    
    html += """
        </div>
        
        <div class="issue">
            <h3>Scenario #2: Brute-Force Attacks</h3>
            <p>Attackers systematically try various combinations of keys until they find the correct one to decrypt the data. Weak cryptography can shorten the time required for such attacks, potentially exposing sensitive information.</p>
    """
    
    # Risk assessment for Brute-Force
    if any("weak" in issue["description"].lower() for issue in results["weak_algorithms"]):
        html += '<p><span class="critical">High Risk</span> - Weak encryption algorithms detected that are vulnerable to brute-force attacks.</p>'
    elif results["weak_algorithms"]:
        html += '<p><span class="high">Medium Risk</span> - Potential weaknesses in cryptographic implementations that might be susceptible to brute-force attacks.</p>'
    else:
        html += '<p><span class="low">Low Risk</span> - No clear weak algorithms detected that would be vulnerable to brute-force attacks.</p>'
    
    html += """
        </div>
        
        <div class="issue">
            <h3>Scenario #3: Cryptographic Downgrade Attacks</h3>
            <p>Mobile applications may support multiple encryption protocols or algorithms to establish secure connections. If weak cryptography is allowed as a fallback option, attackers can exploit this weakness and force the application to use weak encryption. As a result, they can decrypt the intercepted data more easily and launch subsequent attacks.</p>
    """
    
    # Risk assessment for Downgrade
    if any("ECB" in issue["description"] or "weak" in issue["description"].lower() for issue in results["weak_algorithms"]):
        html += '<p><span class="high">Medium Risk</span> - Presence of weak algorithms detected that could be used in downgrade attacks.</p>'
    elif results["transport_layer_issues"]:
        html += '<p><span class="high">Medium Risk</span> - Potential transport layer vulnerabilities that could enable downgrade attacks.</p>'
    else:
        html += '<p><span class="low">Low Risk</span> - No clear indicators of vulnerability to downgrade attacks.</p>'
    
    html += """
        </div>
        
        <div class="issue">
            <h3>Scenario #4: Key Management Vulnerabilities</h3>
            <p>Weak key management practices can undermine the security of the cryptographic systems used in mobile applications. For example, if encryption keys are stored insecurely or are easily guessable, attackers can gain unauthorized access to the keys and decrypt the encrypted data. This can result in data breaches and privacy violations.</p>
    """
    
    # Risk assessment for Key Management
    if results["key_management_issues"]:
        html += '<p><span class="critical">High Risk</span> - Key management issues detected that could lead to unauthorized access to encryption keys.</p>'
    else:
        html += '<p><span class="low">Low Risk</span> - No clear key management issues detected.</p>'
    
    html += """
        </div>
        
        <div class="issue">
            <h3>Scenario #5: Crypto Implementation Flaws</h3>
            <p>Weak cryptography can also stem from implementation flaws in the mobile application itself. These flaws may include incorrect usage of cryptographic libraries, insecure key generation, improper random number generation, or insecure handling of encryption-related functions. Attackers can exploit these flaws to bypass or weaken the encryption protections.</p>
    """
    
    # Risk assessment for Implementation Flaws
    if results["weak_algorithms"] or results["key_management_issues"]:
        html += '<p><span class="critical">High Risk</span> - Potential implementation flaws detected in cryptographic functions.</p>'
    else:
        html += '<p><span class="low">Low Risk</span> - No clear implementation flaws detected.</p>'
    
    html += """
        </div>
        
        <h2>Recommendations</h2>
        <ul>
            <li>Use Strong Encryption Algorithms: Implement widely accepted and secure encryption algorithms, such as AES (Advanced Encryption Standard), RSA (Rivest-Shamir-Adleman), or Elliptic Curve Cryptography (ECC).</li>
            <li>Ensure Sufficient Key Length: Select encryption keys with an appropriate length to ensure strong cryptographic strength (e.g., at least 256 bits for AES).</li>
            <li>Follow Secure Key Management Practices: Employ secure key management techniques, such as using key vaults or hardware security modules (HSMs) to securely store encryption keys.</li>
            <li>Implement Encryption Correctly: Carefully implement encryption and decryption processes adhering to established cryptographic libraries and frameworks.</li>
            <li>Secure Storage of Encryption Keys: Ensure encryption keys are securely stored on the mobile device.</li>
            <li>Employ Secure Transport Layer: Use secure transport layer protocols, such as HTTPS (HTTP Secure), for transmitting encrypted data over networks.</li>
            <li>Validate and Authenticate: Implement strong validation and authentication mechanisms to verify the integrity and authenticity of parties involved in the encryption process.</li>
            <li>Regularly Update Security Measures: Stay informed about security updates, patches, and recommendations from cryptographic libraries.</li>
        </ul>
        
        <h2>Conclusion</h2>
        <p>Based on the analysis performed, the application's cryptographic security posture is 
    """
    
    if severity > 70:
        html += "critically vulnerable and requires immediate attention to address the identified issues."
    elif severity > 40:
        html += "at high risk and requires significant improvements to enhance its cryptographic security."
    elif severity > 20:
        html += "at moderate risk, with some areas requiring improvement to enhance cryptographic security."
    else:
        html += "relatively secure from a cryptographic perspective, with minor or no issues detected."
    
    html += """
        </p>
        <p>Implementing the recommendations provided will help strengthen the application's cryptographic security and protect sensitive data from unauthorized access and potential breaches.</p>
        
        <footer>
            <p>Generated by Mobile App Cryptography Analyzer</p>
            <p>Report generated on: """ + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </footer>
    </body>
    </html>
    """
    
    return html


def main():
    # Create Qt application
    app = QApplication(sys.argv)
    
    # Create and show the main window
    window = MainWindow()
    
    # Start the event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()