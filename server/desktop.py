#!/usr/bin/env python3
"""
Industry-Level Network Intrusion Detection System (NIDS)
Desktop Application

Features:
- Auto-detects network interfaces
- Real-time traffic monitoring with ML-based anomaly detection
- Professional UI with live charts and alerts
- SOC Analyst Reporting (CSV Export & Log Auditing)
- Cross-platform desktop application
"""

import sys
import os
import threading
import time
import subprocess
import csv
import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QMessageBox, QFileDialog, QAction
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QIcon

# Import our Flask app
# Ensure your folder structure has 'server' as a module containing server.py
from server import app, socketio

class FlaskThread(QObject):
    """Runs Flask server in a separate thread"""
    server_started = pyqtSignal(str)  # Signal when server is ready

    def __init__(self):
        super().__init__()
        self.server_thread = None
        self.running = False

    def start_server(self):
        """Start Flask server in background thread"""
        if self.running:
            return

        def run_server():
            try:
                self.running = True
                print("[*] Starting Flask server for desktop app...")
                # Run on localhost:5000
                socketio.run(app, host='127.0.0.1', port=5000, debug=False)
            except Exception as e:
                print(f"[!] Server error: {e}")
            finally:
                self.running = False

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Wait a bit for server to start
        time.sleep(2)
        self.server_started.emit("http://127.0.0.1:5000")

    def stop_server(self):
        """Stop the Flask server"""
        self.running = False
        if self.server_thread and self.server_thread.is_alive():
            # Note: This won't immediately stop the server, but it will when the app closes
            pass

class NIDSDesktopApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.flask_thread = FlaskThread()
        self.flask_thread.server_started.connect(self.on_server_started)

        # Determine log path dynamically based on script location
        HOME_DIR = os.path.expanduser("~")
        self.log_path = os.path.join(HOME_DIR, ".nids_app", "nids.log") # Fallback to current directory

        self.init_ui()
        self.start_flask_server()

    def init_ui(self):
        """Initialize the desktop UI"""
        self.setWindowTitle("NIDS - Security Operations Center")
        self.setGeometry(100, 100, 1400, 900)

        # Set window icon if available
        try:
            # You can add an icon file later
            pass
        except:
            pass

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout
        layout = QVBoxLayout(central_widget)

        # Web view for the Flask app
        self.web_view = QWebEngineView()
        self.web_view.setUrl(QUrl("about:blank"))  # Will be set when server starts

        layout.addWidget(self.web_view)

        # Status bar
        self.statusBar().showMessage("Starting NIDS server...")

        # Menu bar
        self.create_menu_bar()

    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('File')
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # SOC Reporting Menu (NEW FEATURE)
        report_menu = menubar.addMenu('SOC Reporting')
        
        export_action = QAction('Export Incident Report (CSV)', self)
        export_action.triggered.connect(self.export_soc_report)
        report_menu.addAction(export_action)

        view_logs_action = QAction('Open Raw System Logs', self)
        view_logs_action.triggered.connect(self.open_raw_logs)
        report_menu.addAction(view_logs_action)

        # Help menu
        help_menu = menubar.addMenu('Help')
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def export_soc_report(self):
        """Export system logs into a SOC-friendly CSV format"""
        if not os.path.exists(self.log_path):
            QMessageBox.warning(self, "Report Error", "No log file found. Ensure the monitor has generated traffic logs.")
            return

        options = QFileDialog.Options()
        default_filename = f"SOC_Incident_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save SOC Incident Report",
            default_filename,
            "CSV Files (*.csv);;All Files (*)", 
            options=options
        )

        if file_path:
            try:
                with open(self.log_path, 'r') as f:
                    lines = f.readlines()

                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write Header
                    writer.writerow(['Timestamp', 'Module', 'Severity Level', 'Event Details'])

                    # Parse logs and format them nicely for the CSV
                    for line in lines:
                        parts = line.strip().split(' - ', 3)
                        if len(parts) == 4:
                            writer.writerow(parts)
                        else:
                            writer.writerow([line.strip(), '', '', ''])

                QMessageBox.information(self, "Report Generated", f"SOC Incident Report successfully saved to:\n\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"An error occurred while saving the report:\n{str(e)}")

    def open_raw_logs(self):
        """Open the raw nids.log file in the system's default text editor"""
        if not os.path.exists(self.log_path):
            QMessageBox.warning(self, "Not Found", "Log file does not exist yet. Run the monitor first.")
            return

        try:
            if sys.platform.startswith('darwin'):       # macOS
                subprocess.call(('open', self.log_path))
            elif os.name == 'nt':                       # Windows
                os.startfile(self.log_path)
            elif os.name == 'posix':                    # Linux
                subprocess.call(('xdg-open', self.log_path))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open log file:\n{str(e)}")

    def start_flask_server(self):
        """Start the Flask server in background"""
        self.flask_thread.start_server()

    def on_server_started(self, url):
        """Called when Flask server is ready"""
        self.statusBar().showMessage("NIDS server running - Ready to monitor network traffic")
        self.web_view.setUrl(QUrl(url))

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About CyberGuard NIDS",
            "Network Intrusion Detection System\n\n"
            "Features:\n"
            "• Real-time network traffic analysis\n"
            "• Machine learning anomaly detection\n"
            "• Automated SOC Analyst Reporting\n"
            "• Live interactive monitoring dashboard\n\n"
            "Built with Python, Flask, Scapy, and PyQt5."
        )

    def closeEvent(self, event):
        """Handle application close"""
        reply = QMessageBox.question(
            self, 'Confirm Exit',
            'Are you sure you want to exit the Security Operations Center?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.flask_thread.stop_server()
            event.accept()
        else:
            event.ignore()

def check_privileges():
    """Check if running with necessary privileges for packet sniffing"""
    try:
        # Try to run a simple scapy command to check privileges
        import scapy.all as scapy
        scapy.get_if_list()  # This might require privileges
        return True
    except Exception as e:
        return False

def main():
    """Main application entry point"""
    # Check privileges
    if not check_privileges():
        app = QApplication(sys.argv)
        QMessageBox.warning(
            None, "Privilege Warning",
            "NIDS requires elevated privileges to capture network packets.\n\n"
            "Please run this application with administrator/sudo privileges:\n\n"
            "Linux/Mac: sudo venv/bin/python desktop_app.py\n"
            "Windows: Run as Administrator"
        )
        sys.exit(1)

    # Check if display is available (for headless environments)
    if not os.environ.get('DISPLAY') and sys.platform.startswith('linux'):
        print("⚠️  No display detected. This appears to be a headless environment.")
        print("   The desktop app requires a graphical display to run.")
        print("   You can run the web version instead:")
        print("   cd server && sudo ../venv/bin/python server.py")
        print("   Then open http://localhost:5000 in a web browser")
        sys.exit(1)

    # Create Qt application
    # Disable Chromium sandbox for root users (required for packet sniffing)
    if os.geteuid() == 0 if hasattr(os, 'geteuid') else False:
        os.environ['QT_XCB_GL_INTEGRATION'] = 'none'
        os.environ['QT_QPA_PLATFORM'] = 'xcb'
        os.environ['QTWEBENGINE_DISABLE_SANDBOX'] = '1'
        sys.argv.append('--no-sandbox')
        sys.argv.append('--disable-web-security')
        sys.argv.append('--disable-features=VizDisplayCompositor')
    
    app = QApplication(sys.argv)
    app.setApplicationName("CyberGuard NIDS")
    app.setApplicationVersion("1.0")

    # Create main window
    window = NIDSDesktopApp()
    window.show()

    # Run event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()