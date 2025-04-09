import sys  # Helps interact with the system
import os  # Works with the operating system
import zipfile  # Opens ZIP files like XAPK or IPA
import subprocess  # Runs external commands like 'apktool' or 'otool'
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QMessageBox, QProgressBar,
                             QFrame, QScrollArea, QDialog, QTextBrowser)  # Parts of PyQt6 for building the UI
from PyQt6.QtCore import Qt, QThread, pyqtSignal  # For threading and signals
from PyQt6.QtGui import QFont, QColor, QPalette  # For fonts and colors
from androguard.misc import AnalyzeAPK  # Tool to analyze DEX in APK files
from androguard.core.dex import EncodedMethod  # Handles methods in DEX code
from androguard.core.axml import AXMLPrinter  # Reads AndroidManifest.xml from APK directly
from lxml import etree  # Parses XML files like AndroidManifest.xml
import tempfile  # Creates temporary files or folders
import webbrowser  # Opens URLs or email clients
from reportlab.lib.pagesizes import letter  # Sets PDF page size
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer  # Tools to create PDFs
from reportlab.lib.styles import getSampleStyleSheet  # Styles for PDFs
import platform  # Detects the operating system (Windows, Mac, etc.)
import glob  # Finds files using wildcard patterns (for Smali)
import plistlib  # Reads Info.plist files in iOS IPA

# Colors for a modern dark theme
BACKGROUND_COLOR = "#1A1A1A"  # Deep black for background
CARD_COLOR = "#2D2D2D"        # Dark gray for cards
ACCENT_COLOR = "#8B5CF6"      # Deep purple for highlights
HOVER_COLOR = "#A78BFA"       # Light purple for hover effects
TEXT_COLOR = "#D1D5DB"        # Light gray for text
ERROR_COLOR = "#F44336"       # Red for errors
SUCCESS_COLOR = "#4CAF50"     # Green for success messages

# Path to apktool (change this to where apktool.jar is on your system)
APKTOOL_PATH = "apktool.jar"  # Location of apktool.jar, must be on your system
MAX_FILE_SIZE_MB = 100  # Max file size in MB to avoid crashes (adjust as needed)

class AnalysisThread(QThread):  # Class for running analysis in the background
    update_signal = pyqtSignal(str)  # Signal to update the UI
    finished_signal = pyqtSignal(list)  # Signal to send results when done

    def __init__(self, file_path, file_type):  # Sets up the thread
        super().__init__()  # Starts the parent QThread class
        self.file_path = file_path  # Saves the file path
        self.file_type = file_type  # Saves the file type (apk, xapk, ipa)
        self.temp_dir = None  # Variable for temporary folder (empty at first)
        self.decompile_dir = None  # Variable for decompiled files folder

    def run(self):  # Main work of the thread happens here
        try:  # Try block to catch errors
            # Check file size before starting
            file_size_mb = os.path.getsize(self.file_path) / (1024 * 1024)  # Size in MB
            if file_size_mb > MAX_FILE_SIZE_MB:  # If file is too big
                self.finished_signal.emit([f"File too large ({file_size_mb:.2f} MB). Max allowed is {MAX_FILE_SIZE_MB} MB."])
                return  

            if self.file_type in ['apk', 'xapk']:  # If the file is for Android
                apk_file = self.file_path  # Use the given file path
                if self.file_type == 'xapk':  # If it’s an XAPK
                    apk_file = self.extract_xapk()  # Extract APK from XAPK
                    if not apk_file:  # If extraction fails
                        self.finished_signal.emit(["Failed to extract XAPK"])  # Send failure message
                        return  
                apk, _, dx = AnalyzeAPK(apk_file)  # Analyze APK with Androguard for DEX
                vulnerabilities = self.static_analysis_apk(apk, dx, apk_file)  # Do static analysis (DEX, manifest, Smali)
            elif self.file_type == 'ipa':  # If the file is for iOS
                vulnerabilities = self.static_analysis_ipa()  # Do static analysis on IPA
            else: 
                vulnerabilities = ["Unsupported file type"]  # Set default result
            self.finished_signal.emit(vulnerabilities)  # Send results to UI
        except MemoryError:  # If memory runs out
            self.finished_signal.emit(["Crashed due to low memory while scanning large file."])
        except Exception as e:  # If any other error happens
            self.finished_signal.emit([f"Analysis failed: {str(e)}"])  # Send error message
        finally:  # This runs no matter what
            if self.temp_dir:  # If a temp folder was made
                self.cleanup_temp_dir()  # Clean it up
            if self.decompile_dir:  # If a decompile folder was made
                self.cleanup_decompile_dir()  # Clean it up too

    def extract_xapk(self):  # Function to extract APK from XAPK
        self.update_signal.emit("Unpacking the XAPK file...")  # Tell UI unpacking started
        self.temp_dir = tempfile.mkdtemp()  # Create a temporary folder
        try:  # Try to open the ZIP
            with zipfile.ZipFile(self.file_path, 'r') as z:  # Open XAPK as a ZIP
                apk_files = [f for f in z.infolist() if f.filename.endswith('.apk')]  # Find all APK files
                base_apk = next((f for f in apk_files if 'base' in f.filename.lower()), apk_files[0])  # Pick base APK
                extracted_path = z.extract(base_apk, self.temp_dir)  # Extract APK to temp folder
                self.update_signal.emit(f"Extracted APK: {os.path.basename(extracted_path)}")  # Update UI
                return extracted_path  # Return path to extracted APK
        except zipfile.BadZipFile:  # If the ZIP is broken
            return None  # Return nothing

    def cleanup_temp_dir(self):  # Function to clean up the temporary folder
        if self.temp_dir and os.path.exists(self.temp_dir):  # If temp folder exists
            for root, dirs, files in os.walk(self.temp_dir, topdown=False):  # Go through the folder
                for name in files:  # For each file
                    os.remove(os.path.join(root, name))  # Delete the file
                for name in dirs:  # For each subfolder
                    os.rmdir(os.path.join(root, name))  # Delete the subfolder
            os.rmdir(self.temp_dir)  # Delete the temp folder itself

    def cleanup_decompile_dir(self):  # Function to clean up the decompiled folder
        if self.decompile_dir and os.path.exists(self.decompile_dir):  # If decompile folder exists
            for root, dirs, files in os.walk(self.decompile_dir, topdown=False):  # Go through the folder
                for name in files:  # For each file
                    os.remove(os.path.join(root, name))  # Delete the file
                for name in dirs:  # For each subfolder
                    os.rmdir(os.path.join(root, name))  # Delete the subfolder
            os.rmdir(self.decompile_dir)  # Delete the decompile folder itself

    def decompile_apk(self, apk_file):  # Function to decompile the APK
        self.update_signal.emit("Decompiling APK to get Smali files...")  # Tell UI decompiling started
        self.decompile_dir = tempfile.mkdtemp()  # Create a temporary folder for decompiled files
        try:  # Try to run apktool
            subprocess.run(['java', '-jar', APKTOOL_PATH, 'd', apk_file, '-f', '-o', self.decompile_dir], 
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # Decompile APK
            self.update_signal.emit("APK decompiled successfully.")  # Tell UI decompile worked
            return self.decompile_dir  # Return path to decompiled folder
        except subprocess.CalledProcessError as e:  # If apktool fails
            self.update_signal.emit(f"Failed to decompile APK: {e.stderr.decode()}")  # Send error to UI
            return None  # Return nothing

    def analyze_dex(self, dx):  # Function to analyze DEX files
        self.update_signal.emit("Checking DEX files...")  # Tell UI DEX check started
        vulnerabilities = set()  # Set to store unique vulnerabilities
        weak_algorithms = set()  # Set to store weak algorithms

        for cls in dx.get_classes():  # Check all classes in DEX file
            try:  # Try block to avoid errors
                class_name = cls.get_vm_class().get_name()  # Get class name
                for method in cls.get_methods():  # Check methods in the class
                    raw_method = method.get_method()  # Get raw method object
                    if isinstance(raw_method, EncodedMethod) and raw_method.get_code():  # If method has code
                        for ins in raw_method.get_code().get_bc().get_instructions():  # Check instructions
                            ins_str = ins.get_name() + " " + " ".join(map(str, ins.get_operands()))  # Make instruction string
                            for weak in ['des', 'md5', 'sha1', 'rc4', 'sha', '3des', 'rc2', 'blowfish']:  # Check weak algorithms
                                if weak in ins_str.lower():  # If weak algorithm found
                                    weak_algorithms.add(weak.upper())  # Add to set (in uppercase)
            except Exception as e:  # If error happens in code analysis
                vulnerabilities.add(f"Error analyzing DEX code: {str(e)}")  # Add error to vulnerabilities

        if weak_algorithms:  # If any weak algorithms found
            vulnerabilities.add(f"Detected weak algorithms in DEX: {', '.join(weak_algorithms)}")  # Add to vulnerabilities

        return vulnerabilities  # Return vulnerabilities

    def analyze_manifest(self, apk):  # Function to analyze the manifest file
        self.update_signal.emit("Checking AndroidManifest.xml...")  # Tell UI manifest check started
        vulnerabilities = set()  # Set to store unique vulnerabilities
        
        try:  # Try to parse manifest
            manifest_xml = apk.get_android_manifest_xml()  # Get manifest as XML from APK
            manifest_str = etree.tostring(manifest_xml, encoding='unicode').lower()  # Convert to string in lowercase
        except Exception:  # If XML parsing fails
            raw_manifest = apk.get_file('AndroidManifest.xml')  # Get raw manifest file from APK
            axml = AXMLPrinter(raw_manifest)  # Parse with AXMLPrinter
            manifest_str = axml.get_buff().decode('utf-8', errors='ignore')  # Decode to string

        # Check for risky permissions and settings (same as IPA settings where applicable)
        if 'android.permission.write_external_storage' in manifest_str:  # If this permission is found
            vulnerabilities.add("Insecure storage permission detected.")  # Add vulnerability
        if 'android.permission.internet' in manifest_str and 'usescleartexttraffic="false"' not in manifest_str:  # Check for cleartext traffic
            vulnerabilities.add("Potential cleartext traffic (non-HTTPS) detected.")  # Add vulnerability
        
        return vulnerabilities  

    def scan_smali_files(self, decompile_dir):  # Function to scan Smali files
        self.update_signal.emit("Scanning Smali files...")  # Tell UI Smali scanning started
        vulnerabilities = set()  # Set to store unique vulnerabilities
        weak_algorithms = {'des', 'md5', 'sha1', 'rc4', 'sha', '3des', 'rc2', 'blowfish'}  # List of weak algorithms
        
        smali_files = glob.glob(os.path.join(decompile_dir, '**', '*.smali'), recursive=True)  # Find all Smali files
        for smali_file in smali_files:  # For each Smali file
            try:  # Try block to avoid memory overload
                with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:  # Open the file
                    content = f.read(1024 * 1024)  # Read only 1MB at a time to save memory
                    content_lower = content.lower()  # Convert to lowercase
                    for weak in weak_algorithms:  # Check each weak algorithm
                        if weak in content_lower:  # If algorithm is found
                            vulnerabilities.add(f"Detected weak algorithm '{weak.upper()}' in Smali file: {os.path.basename(smali_file)}")  # Add vulnerability
                    if 'const-string' in content_lower and 'key' in content_lower:  # Check for hardcoded keys
                        vulnerabilities.add(f"Possible hardcoded key in Smali file: {os.path.basename(smali_file)}")  # Add vulnerability
            except MemoryError:  # If memory runs out
                vulnerabilities.add(f"Skipped large Smali file due to memory limit: {os.path.basename(smali_file)}")
            except Exception as e:  # If any other error
                vulnerabilities.add(f"Error scanning Smali file {os.path.basename(smali_file)}: {str(e)}")
        
        return vulnerabilities  # Return vulnerabilities

    def static_analysis_apk(self, apk, dx, apk_file):  # Function for static analysis of APK
        vulnerabilities = set()  # Set to store all vulnerabilities
        
        # Analyze DEX
        dex_vulns = self.analyze_dex(dx)  # Check DEX files
        vulnerabilities.update(dex_vulns)  # Add DEX vulnerabilities
        
        # Analyze manifest
        manifest_vulns = self.analyze_manifest(apk)  # Check manifest file
        vulnerabilities.update(manifest_vulns)  # Add manifest vulnerabilities
        
        # Analyze Smali
        decompile_dir = self.decompile_apk(apk_file)  # Decompile the APK
        if decompile_dir:  # If decompile worked
            smali_vulns = self.scan_smali_files(decompile_dir)  # Scan Smali files
            vulnerabilities.update(smali_vulns)  # Add Smali vulnerabilities
        
        return list(vulnerabilities)  # Return list of all vulnerabilities

    def static_analysis_ipa(self):  # Function for static analysis of IPA
        self.update_signal.emit("Analyzing IPA (static)...")  # Tell UI IPA analysis started
        vulnerabilities = set()  # Set to store unique vulnerabilities
        self.temp_dir = tempfile.mkdtemp()  # Create a temp folder for IPA extraction

        try:  # Try block to avoid errors
            # Extract IPA contents
            with zipfile.ZipFile(self.file_path, 'r') as z:  # Open IPA as a ZIP
                z.extractall(self.temp_dir)  # Extract all files to temp folder

            # Check Info.plist (like Android manifest)
            info_plist_path = os.path.join(self.temp_dir, "Payload", "*.app", "Info.plist")  # Find Info.plist in Payload
            info_plist_files = glob.glob(info_plist_path)  # Get matching files
            if info_plist_files:  # If Info.plist is found
                with open(info_plist_files[0], 'rb') as f:  # Open the file
                    info_plist = plistlib.load(f)  # Parse Info.plist
                    # Check for risky settings (like Android permissions)
                    if info_plist.get('NSAppTransportSecurity', {}).get('NSAllowsArbitraryLoads', False):  # Check insecure network settings
                        vulnerabilities.add("Potential cleartext traffic (non-HTTPS) detected.")  # Add vulnerability (same as APK)
                    if info_plist.get('NSCameraUsageDescription') or info_plist.get('NSPhotoLibraryUsageDescription'):  # Check for risky permissions
                        vulnerabilities.add("Insecure storage permission detected (Camera/Photo access).")  # Add vulnerability (like WRITE_EXTERNAL_STORAGE)

            # Check binary with otool and strings (like DEX and Smali)
            app_binary_path = os.path.join(self.temp_dir, "Payload", "*.app", os.path.basename(self.file_path).replace('.ipa', ''))  # Find app binary
            binary_files = glob.glob(app_binary_path)  # Get matching files
            if binary_files:  # If binary is found
                binary_path = binary_files[0]  # Use first binary found
                # Check linked libraries with otool -L (like DEX weak algorithms)
                result = subprocess.run(['otool', '-L', binary_path], capture_output=True, text=True)  # Run otool command
                if result.returncode == 0:  # If command worked
                    libraries = result.stdout.lower()  # Get output in lowercase
                    weak_libs = ['libcrypto', 'libssl']  # Weak crypto libraries to check
                    for lib in weak_libs:  # Check each library
                        if lib in libraries and any(v in libraries for v in ['1.0.0', '0.9']):  # Look for old versions
                            vulnerabilities.add(f"Detected weak library '{lib}' in binary (old version).")  # Add vulnerability

                # Check for weak algorithms and keys with strings (like DEX and Smali)
                weak_algorithms = {'des', 'md5', 'sha1', 'rc4', 'sha', '3des', 'rc2', 'm'}  # Same weak algorithms as APK
                result = subprocess.run(['strings', binary_path], capture_output=True, text=True)  # Run strings command
                if result.returncode == 0:  # If command worked
                    binary_content = result.stdout.lower()  # Get output in lowercase
                    for algo in weak_algorithms:  # Check each weak algorithm
                        if algo in binary_content:  # If found in binary
                            vulnerabilities.add(f"Detected weak algorithm '{algo.upper()}' in binary.")  # Add vulnerability (same as DEX/Smali)
                    if 'key' in binary_content:  # Check for hardcoded keys
                        vulnerabilities.add("Possible hardcoded key in binary.")  # Add vulnerability (same as Smali)

        except MemoryError:  # If memory runs out
            vulnerabilities.add("Crashed due to low memory while scanning large IPA file.")
        except Exception as e:  # If any other error happens
            vulnerabilities.add(f"Error analyzing IPA: {str(e)}")

        return list(vulnerabilities)  # Return list of vulnerabilities

class CryptoAnalyzer(QMainWindow):  # Main window class for the UI
    def __init__(self):  # Sets up the window
        super().__init__()  # Starts the parent QMainWindow class
        self.setWindowTitle("CryptoGuard Analyzer")  # Sets window title
        self.setGeometry(100, 100, 1000, 700)  # Sets window size and position
        self.init_ui()  # Sets up the UI

    def init_ui(self):  # Function to build the UI
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR};")  # Sets background color
        main_widget = QWidget()  # Creates main widget
        self.setCentralWidget(main_widget)  # Makes it the central widget
        layout = QHBoxLayout(main_widget)  # Creates horizontal layout
        layout.setContentsMargins(20, 20, 20, 20)  # Sets margins
        layout.setSpacing(20)  # Sets space between elements

        # Sidebar for navigation
        sidebar = QFrame()  # Creates sidebar frame
        sidebar.setStyleSheet(f"background-color: {CARD_COLOR}; border-radius: 5px; padding: 10px;")  # Sets sidebar style
        sidebar_layout = QVBoxLayout(sidebar)  # Creates vertical layout for sidebar
        
        nav_items = ["How to Use This App", "Export PDF", "Share", "Email"]  # Navigation options
        nav_functions = {  # Maps options to their functions
            "How to Use This App": self.show_how_to_use,
            "Export PDF": self.export_pdf,
            "Share": self.share_results,
            "Email": self.email_results
        }
        for item in nav_items:  # For each navigation item
            nav_button = QPushButton(item)  # Creates a button
            nav_button.setStyleSheet(f"""  # Sets button style
                QPushButton {{
                    background-color: {CARD_COLOR};
                    color: {TEXT_COLOR};
                    border: none;
                    padding: 10px;
                    text-align: left;
                    font-family: 'Open Sans';
                    font-size: 16px;
                }}
                QPushButton:hover {{
                    background-color: {HOVER_COLOR};
                }}
            """)
            if item in nav_functions:  # If it has a function
                nav_button.clicked.connect(nav_functions[item])  # Connects button to function
            sidebar_layout.addWidget(nav_button)  # Adds button to sidebar
        sidebar_layout.addStretch()  # Adds stretch to fill space
        layout.addWidget(sidebar, stretch=1)  # Adds sidebar to layout

        # Main content area
        content_widget = QWidget()  # Creates content widget
        content_layout = QVBoxLayout(content_widget)  # Creates vertical layout for content

        # Header section
        header_layout = QHBoxLayout()  # Creates horizontal layout for header
        logo_label = QLabel("CryptoGuard Analyzer")  # Creates logo label
        logo_label.setFont(QFont("Open Sans", 24, QFont.Weight.Bold))  # Sets font
        logo_label.setStyleSheet(f"color: {ACCENT_COLOR};")  # Sets color
        header_layout.addWidget(logo_label)  # Adds logo to header
        
        status_layout = QHBoxLayout()  # Creates layout for status
        self.static_status = QLabel("Analysis: Ready")  # Status label
        self.static_status.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 14px;")  # Sets style
        status_layout.addWidget(self.static_status)  # Adds status
        header_layout.addLayout(status_layout)  # Adds status layout to header
        
        header_layout.addStretch()  # Adds stretch to fill space
        profile_label = QLabel("👤")  # Profile icon label
        profile_label.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 24px;")  # Sets style
        header_layout.addWidget(profile_label)  # Adds profile to header
        content_layout.addLayout(header_layout)  # Adds header to content

        # Central content area with tiles
        central_frame = QFrame()  # Creates central frame
        central_frame.setStyleSheet(f"background-color: {CARD_COLOR}; border-radius: 5px; padding: 15px;")  # Sets style
        central_layout = QVBoxLayout(central_frame)  # Creates vertical layout for frame

        # File selection tile
        file_tile = QFrame()  # Creates file selection tile
        file_tile.setStyleSheet(f"background-color: {ACCENT_COLOR}; border-radius: 5px; padding: 10px;")  # Sets style
        file_tile_layout = QHBoxLayout(file_tile)  # Creates horizontal layout for tile
        file_icon = QLabel("📁")  # File icon
        file_icon.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 24px;")  # Sets style
        file_tile_layout.addWidget(file_icon)  # Adds icon to tile
        self.file_label = QLabel("Select File")  # Label for file
        self.file_label.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 18px;")  # Sets style
        file_tile_layout.addWidget(self.file_label)  # Adds label to tile
        file_tile_layout.addStretch()  # Adds stretch to fill space
        select_button = QPushButton("Browse")  # Browse button
        select_button.setStyleSheet(f"""  # Sets button style
            QPushButton {{
                background-color: {HOVER_COLOR};
                border-radius: 5px;
                padding: 5px 10px;
                color: #FFFFFF;
                font-family: 'Open Sans';
            }}
            QPushButton:hover {{
                background-color: {ACCENT_COLOR};
            }}
        """)
        select_button.clicked.connect(self.select_file)  # Connects button to file selection
        file_tile_layout.addWidget(select_button)  # Adds button to tile
        central_layout.addWidget(file_tile)  # Adds tile to central layout

        # Analysis tile
        analysis_tile = QFrame()  # Creates analysis tile
        analysis_tile.setStyleSheet(f"background-color: {ACCENT_COLOR}; border-radius: 5px; padding: 10px;")  # Sets style
        analysis_tile_layout = QHBoxLayout(analysis_tile)  # Creates horizontal layout for tile
        analysis_icon = QLabel("🔍")  # Analysis icon
        analysis_icon.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 24px;")  # Sets style
        analysis_tile_layout.addWidget(analysis_icon)  # Adds icon to tile
        analysis_label = QLabel("Start Analysis")  # Analysis label
        analysis_label.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 18px;")  # Sets style
        analysis_tile_layout.addWidget(analysis_label)  # Adds label to tile
        analysis_tile_layout.addStretch()  # Adds stretch to fill space
        self.analyze_button = QPushButton("Analyze")  # Analyze button
        self.analyze_button.setStyleSheet(f"""  # Sets button style
            QPushButton {{
                background-color: {HOVER_COLOR};
                border-radius: 5px;
                padding: 5px 10px;
                color: #FFFFFF;
                font-family: 'Open Sans';
            }}
            QPushButton:hover {{
                background-color: {ACCENT_COLOR};
            }}
            QPushButton:disabled {{
                background-color: #4B5563;
            }}
        """)
        self.analyze_button.clicked.connect(self.analyze_file)  # Connects button to analysis
        self.analyze_button.setEnabled(False)  # Disables button at start
        analysis_tile_layout.addWidget(self.analyze_button)  # Adds button to tile
        central_layout.addWidget(analysis_tile)  # Adds tile to central layout

        # Reset tile
        reset_tile = QFrame()  # Creates reset tile
        reset_tile.setStyleSheet(f"background-color: {ACCENT_COLOR}; border-radius: 5px; padding: 10px;")  # Sets style
        reset_tile_layout = QHBoxLayout(reset_tile)  # Creates horizontal layout for tile
        reset_icon = QLabel("🔄")  # Reset icon
        reset_icon.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 24px;")  # Sets style
        reset_tile_layout.addWidget(reset_icon)  # Adds icon to tile
        reset_label = QLabel("Reset")  # Reset label
        reset_label.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 18px;")  # Sets style
        reset_tile_layout.addWidget(reset_label)  # Adds label to tile
        reset_tile_layout.addStretch()  # Adds stretch to fill space
        self.reset_button = QPushButton("Reset")  # Reset button
        self.reset_button.setStyleSheet(f"""  # Sets button style
            QPushButton {{
                background-color: {HOVER_COLOR};
                border-radius: 5px;
                padding: 5px 10px;
                color: #FFFFFF;
                font-family: 'Open Sans';
            }}
            QPushButton:hover {{
                background-color: {ACCENT_COLOR};
            }}
        """)
        self.reset_button.clicked.connect(self.reset_analysis)  # Connects button to reset
        reset_tile_layout.addWidget(self.reset_button)  # Adds button to tile
        central_layout.addWidget(reset_tile)  # Adds tile to central layout

        content_layout.addWidget(central_frame)  # Adds central frame to content

        # Progress bar
        self.progress_bar = QProgressBar()  # Creates progress bar
        self.progress_bar.setVisible(False)  # Hides it at start
        self.progress_bar.setStyleSheet(f"""  # Sets progress bar style
            QProgressBar {{
                background-color: {CARD_COLOR};
                border-radius: 5px;
                padding: 5px;
                border: 1px solid {ACCENT_COLOR};
                text-align: center;
                color: {TEXT_COLOR};
                font-family: 'Open Sans';
            }}
            QProgressBar::chunk {{
                background-color: {HOVER_COLOR};
                border-radius: 3px;
            }}
        """)
        content_layout.addWidget(self.progress_bar)  # Adds progress bar to content

        # Scanning log area
        self.scan_log = QTextEdit()  # Creates text area for scan log
        self.scan_log.setFont(QFont("Open Sans", 16))  # Sets font
        self.scan_log.setReadOnly(True)  # Makes it read-only
        self.scan_log.setStyleSheet(f"""  # Sets scan log style
            QTextEdit {{
                background-color: {CARD_COLOR};
                border-radius: 5px;
                padding: 15px;
                color: {TEXT_COLOR};
                border: 1px solid {ACCENT_COLOR};
            }}
        """)
        self.scan_log.setVisible(False)  # Hides it at start
        content_layout.addWidget(self.scan_log)  # Adds scan log to content

        # Results frame
        self.results_frame = QFrame()  # Creates frame for results
        self.results_frame.setStyleSheet(f"""  # Sets results frame style
            background-color: {CARD_COLOR};
            border-radius: 5px;
            padding: 15px;
            border: 1px solid {ACCENT_COLOR};
        """)
        results_layout = QVBoxLayout(self.results_frame)  # Creates vertical layout for results

        self.results_text = QTextEdit()  # Creates text area for results
        self.results_text.setFont(QFont("Open Sans", 16))  # Sets font
        self.results_text.setReadOnly(True)  # Makes it read-only
        self.results_text.setStyleSheet(f"""  # Sets results text style
            QTextEdit {{
                background-color: {BACKGROUND_COLOR};
                border-radius: 5px;
                padding: 15px;
                color: {TEXT_COLOR};
                border: 1px solid #6B7280;
            }}
        """)
        scroll = QScrollArea()  # Creates scroll area for results
        scroll.setWidget(self.results_text)  # Puts results text in scroll area
        scroll.setWidgetResizable(True)  # Allows resizing
        scroll.setStyleSheet(f"""  # Sets scroll area style
            QScrollArea {{
                background-color: transparent;
                border: none;
            }}
            QScrollBar:vertical {{
                background-color: {CARD_COLOR};
                width: 12px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {ACCENT_COLOR};
                border-radius: 2px;
            }}
        """)
        results_layout.addWidget(scroll)  # Adds scroll area to results
        content_layout.addWidget(self.results_frame, stretch=3)  # Adds results frame to content

        layout.addWidget(content_widget, stretch=3)  # Adds content widget to main layout

    def show_how_to_use(self):  # Function to show "How to Use" dialog
        how_to_dialog = QDialog(self)  # Creates dialog
        how_to_dialog.setWindowTitle("How to Use CryptoGuard Analyzer")  # Sets title
        how_to_dialog.setGeometry(300, 300, 400, 300)  # Sets size and position
        layout = QVBoxLayout(how_to_dialog)  # Creates layout for dialog
        text = QTextBrowser()  # Creates text area for instructions
        text.setHtml("""  # Sets instructions in HTML
            <h2>How to Use CryptoGuard Analyzer</h2>
            <ol>
                <li><b>Select File:</b> Click "Browse" to choose an APK, XAPK, or IPA file.</li>
                <li><b>Analyze:</b> Click "Analyze" to check the file.</li>
                <li><b>View Results:</b> See the results for any issues and risks.</li>
                <li><b>Export/Share:</b> Use "Export PDF," "Share," or "Email" to save or send results.</li>
                <li><b>Reset:</b> Click "Reset" to clear the current analysis.</li>
            </ol>
        """)
        layout.addWidget(text)  # Adds text to dialog
        how_to_dialog.exec()  # Shows dialog

    def export_pdf(self):  # Function to save results as PDF
        if not self.results_text.toPlainText():  # If no results exist
            QMessageBox.warning(self, "Error", "No analysis results to export!")  # Shows warning
            return  # Exits function

        file_path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF Files (*.pdf)")  # Opens save dialog
        if file_path:  # If a file path is chosen
            doc = SimpleDocTemplate(file_path, pagesize=letter)  # Creates PDF document
            styles = getSampleStyleSheet()  # Gets styles for PDF
            story = []  # List for PDF content

            results = self.results_text.toHtml().replace('<br>', '\n').replace('<b>', '').replace('</b>', '')  # Cleans HTML
            for line in results.split('\n'):  # Processes each line
                if '<h3' in line:  # If it’s a heading
                    story.append(Paragraph(line.replace('<h3', '').replace('</h3>', '').strip(), styles['Heading1']))  # Adds heading
                elif '<li' in line:  # If it’s a list item
                    story.append(Paragraph(f"• {line.replace('<li', '').replace('</li>', '').strip()}", styles['BodyText']))  # Adds bullet
                else:  # For other text
                    story.append(Paragraph(line.strip(), styles['BodyText']))  # Adds paragraph
                story.append(Spacer(1, 12))  # Adds space

            doc.build(story)  # Builds PDF
            QMessageBox.information(self, "Success", f"Results exported to {file_path}")  # Shows success message

    def share_results(self):  # Function to copy results to clipboard
        if not self.results_text.toPlainText():  # If no results exist
            QMessageBox.warning(self, "Error", "No analysis results to share!")  # Shows warning
            return  # Exits function

        results = self.results_text.toPlainText()  # Gets results as text
        if platform.system() == "Windows":  # If on Windows
            subprocess.run(['clip'], input=results.encode('utf-8'), check=True)  # Copies to clipboard
            QMessageBox.information(self, "Success", "Results copied to clipboard. Paste them into your preferred sharing app.")  # Shows success
        elif platform.system() == "Darwin":  # If on macOS
            subprocess.run(['pbcopy'], input=results.encode('utf-8'), check=True)  # Copies to clipboard
            QMessageBox.information(self, "Success", "Results copied to clipboard. Paste them into your preferred sharing app.")  # Shows success
        else:  # If on Linux or other OS
            try:  # Tries for Linux
                subprocess.run(['xclip', '-selection', 'clipboard'], input=results.encode('utf-8'), check=True)  # Copies to clipboard
                QMessageBox.information(self, "Success", "Results copied to clipboard. Paste them into your preferred sharing app.")  # Shows success
            except FileNotFoundError:  # If xclip isn’t installed
                QMessageBox.warning(self, "Error", "xclip not found. Please install it to use this feature.")  # Shows error

    def email_results(self):  # Function to email results
        if not self.results_text.toPlainText():  # If no results exist
            QMessageBox.warning(self, "Error", "No analysis results to email!")  # Shows warning
            return  # Exits function

        subject = "CryptoGuard Analyzer Results"  # Email subject
        body = self.results_text.toPlainText().replace('\n', '%0D%0A')  # Formats body for URL
        mailto_url = f"mailto:?subject={subject}&body={body}"  # Creates mailto URL
        webbrowser.open(mailto_url)  # Opens email client

    def select_file(self):  # Function to select a file
        file_path, _ = QFileDialog.getOpenFileName(self, "Select APK or IPA File", "",
                                                   "App Files (*.apk *.xapk *.ipa);;All Files (*)")  # Opens file dialog
        if file_path:  # If a file is chosen
            self.file_path = file_path  # Saves file path
            self.file_label.setText(f"Selected: {os.path.basename(file_path)}")  # Updates label
            self.analyze_button.setEnabled(True)  # Enables analyze button
            self.results_text.clear()  # Clears old results
            self.scan_log.clear()  # Clears scan log
            self.scan_log.setVisible(False)  # Hides scan log

    def reset_analysis(self):  # Function to reset analysis
        self.file_label.setText("Select File")  # Resets file label
        self.analyze_button.setEnabled(False)  # Disables analyze button
        self.results_text.clear()  # Clears results
        self.scan_log.clear()  # Clears scan log
        self.scan_log.setVisible(False)  # Hides scan log
        self.static_status.setText("Analysis: Ready")  # Resets status

    def analyze_file(self):  # Function to analyze the file
        if not hasattr(self, 'file_path'):  # If no file is selected
            QMessageBox.warning(self, "Error", "Please select a file first!")  # Shows warning
            return  # Exits function

        file_ext = os.path.splitext(self.file_path)[1].lower()[1:]  # Gets file extension
        self.results_text.clear()  # Clears old results
        self.scan_log.clear()  # Clears scan log
        self.scan_log.setVisible(True)  # Shows scan log
        self.results_frame.setVisible(False)  # Hides results frame
        self.analyze_button.setEnabled(False)  # Disables analyze button
        self.progress_bar.setVisible(True)  # Shows progress bar
        self.progress_bar.setValue(0)  # Resets progress bar
        self.static_status.setText("Analysis: Running...")  # Updates status

        self.thread = AnalysisThread(self.file_path, file_ext)  # Creates analysis thread
        self.thread.update_signal.connect(self.update_scan_log)  # Connects update signal
        self.thread.finished_signal.connect(self.display_results)  # Connects finished signal
        self.thread.start()  # Starts thread

    def update_scan_log(self, message):  # Function to update scan log
        self.scan_log.append(f"<i>{message}</i>")  # Adds message to log
        current_value = self.progress_bar.value()  # Gets current progress value
        self.progress_bar.setValue(min(current_value + 20, 80))  # Increases progress (max 80)

    def display_results(self, vulnerabilities):  # Function to show results
        self.progress_bar.setValue(100)  # Sets progress to 100%
        self.progress_bar.setVisible(False)  # Hides progress bar
        self.scan_log.setVisible(False)  # Hides scan log
        self.results_frame.setVisible(True)  # Shows results frame
        self.analyze_button.setEnabled(True)  # Enables analyze button
        self.static_status.setText("Analysis: Complete")  # Updates status

        self.results_text.append("<hr><h3 style='color: #8B5CF6;'>Analysis Results</h3>")  # Adds results header
        if vulnerabilities:  # If vulnerabilities exist
            self.results_text.append("<ul style='margin-left: 20px;'>")  # Starts list
            for vuln in vulnerabilities:  # For each vulnerability
                self.results_text.append(f"<li style='color: #F44336;'>{vuln}</li>")  # Adds list item
             # Ends list
        else:  # If no vulnerabilities
            self.results_text.append("<p style='color: #4CAF50;'>✔ No issues found.</p>")  # Adds success message

        # Check for attack scenarios based on vulnerabilities
        self.results_text.append("<h3 style='color: #8B5CF6;'>Potential Risks</h3>")  # Adds risks header
        combined_vulns = " ".join(vulnerabilities).lower()  # Combines all vulnerabilities into one string
        risks = []  # List to store risks

        # Scenario #1: Man-in-the-Middle (MitM) Attacks
        if "cleartext" in combined_vulns or "insecure" in combined_vulns:  # Check for network-related issues
            risks.append("Scenario #1: Man-in-the-Middle (MitM) Attacks - An attacker intercepts the communication between the mobile app and server. Weak cryptography can enable attackers to decrypt the intercepted data, modify it, and re-encrypt it before forwarding it to the intended recipient. This can lead to unauthorized access, data manipulation, or injection of malicious content.")  # Adds MitM scenario

        # Scenario #2: Brute-Force Attacks
        if "weak" in combined_vulns:  # Check for weak algorithms
            risks.append("Scenario #2: Brute-Force Attacks - Attackers systematically try various combinations of keys until they find the correct one to decrypt the data. Weak cryptography can shorten the time required for such attacks, potentially exposing sensitive information.")  # Adds brute-force scenario

        # Scenario #3: Cryptographic Downgrade Attacks
        if "weak" in combined_vulns or "insecure" in combined_vulns:  # Check for weak or insecure settings
            risks.append("Scenario #3: Cryptographic Downgrade Attacks - Mobile apps may support multiple encryption protocols or algorithms. If weak cryptography is allowed as a fallback option, attackers can exploit this weakness and force the app to use weak encryption, making it easier to decrypt data and launch further attacks.")  # Adds downgrade scenario

        # Scenario #4: Key Management Vulnerabilities
        if "hardcoded" in combined_vulns or "key" in combined_vulns:  # Check for key-related issues
            risks.append("Scenario #4: Key Management Vulnerabilities - Weak key management practices, like insecurely stored or easily guessable keys, can undermine security. Attackers can gain unauthorized access to these keys and decrypt the data, leading to breaches and privacy violations.")  # Adds key management scenario

        # Scenario #5: Crypto Implementation Flaws
        if "weak" in combined_vulns or "insecure" in combined_vulns or "error" in combined_vulns:  # Check for implementation issues
            risks.append("Scenario #5: Crypto Implementation Flaws - Weak cryptography can come from flaws in the app, like incorrect use of crypto libraries, insecure key generation, or poor random number generation. Attackers can exploit these flaws to bypass or weaken encryption protections.")  # Adds implementation flaws scenario

        if risks:  # If risks exist
            self.results_text.append("<ul style='margin-left: 20px;'>")  # Starts list
            for risk in risks:  # For each risk
                self.results_text.append(f"<li style='color: #F44336;'>{risk}</li>")  # Adds list item
              # Ends list
            self.results_text.append("<p style='color: #D1D5DB;'>Recommendation: Avoid sensitive data usage or contact the developer.</p>")  # Adds recommendation
        else:  # If no risks
            self.results_text.append("<p style='color: #4CAF50;'>✔ No significant risks detected.</p>")  # Adds success message

if __name__ == '__main__':  # Main starting point of the program
    app = QApplication(sys.argv)  # Creates Qt application
    app.setStyle("Fusion")  # Sets application style
    window = CryptoAnalyzer()  # Creates main window
    window.show()  # Shows the window
    sys.exit(app.exec())  # Runs application and returns exit code