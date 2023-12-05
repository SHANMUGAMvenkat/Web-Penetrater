import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import scrolledtext
from ttkthemes import ThemedStyle
import subprocess
import sys
import json
from bs4 import BeautifulSoup
import requests


class Vulnerability:
    def __init__(self, name, severity, description):
        self.name = name
        self.severity = severity
        self.description = description


class VulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title('Web Vulnerability Scanner')
        self.root.geometry('800x550')

        self.tabs = ttk.Notebook(root)
        self.tab1 = ttk.Frame(self.tabs)
        self.tab2 = ttk.Frame(self.tabs)
        self.tab3 = ttk.Frame(self.tabs)
        self.tab4 = ttk.Frame(self.tabs)
        self.tab6 = ttk.Frame(self.tabs)

        self.create_scan_tab()
        self.create_upload_tab()
        self.create_report_tab()
        self.create_about_tab()
        self.create_url_validation_tab()

        self.tabs.add(self.tab1, text="Scan")
        self.tabs.add(self.tab2, text="Upload Files")
        self.tabs.add(self.tab3, text="Report")
        self.tabs.add(self.tab6, text="URL Validation")
        self.tabs.add(self.tab4, text="About")
        self.tabs.pack(fill="both", expand=True)

    def create_scan_tab(self):
        self.url_label = ttk.Label(self.tab1, text='Enter URL:')
        self.url_edit = ttk.Entry(self.tab1)
        self.scan_button = ttk.Button(self.tab1, text='Scan', command=self.scan)
        self.log_box = scrolledtext.ScrolledText(self.tab1, wrap=tk.WORD)
        self.export_button = ttk.Button(self.tab1, text='Export Log')

        self.attacks_label = ttk.Label(self.tab1, text='Select Attacks:')

        # Create a frame to contain the checkboxes on the left
        checkbox_frame = ttk.Frame(self.tab1)
        checkbox_frame.grid(row=2, column=0, padx=5, pady=5, sticky='w')

        self.attack_checkboxes = {
            'SQL Injection': tk.IntVar(),
            'XSS': tk.IntVar(),
            'WHOIS': tk.IntVar(),
            'CSRF': tk.IntVar(),
            'HTTP Tampering': tk.IntVar()
        }

        # Arrange checkboxes on the left side
        for i, (attack, var) in enumerate(self.attack_checkboxes.items()):
            ttk.Checkbutton(checkbox_frame, text=attack, variable=var).grid(row=i, column=0, padx=5, pady=5, sticky='w')

        self.url_label.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.url_edit.grid(row=0, column=2, padx=5, pady=5)
        self.scan_button.grid(row=0, column=3, padx=5, pady=5)
        self.attacks_label.grid(row=1, column=1, padx=5, pady=5, sticky='w')

        self.log_box.grid(row=2, column=1, columnspan=3, padx=5, pady=5)
        self.export_button.grid(row=3, column=1, padx=5, pady=5, sticky='w')

    def create_upload_tab(self):
        self.file_label = ttk.Label(self.tab2, text='Select File for Analysis:')
        self.file_edit = ttk.Entry(self.tab2)
        self.browse_button = ttk.Button(self.tab2, text='Browse', command=self.browse_file)
        self.upload_button = ttk.Button(self.tab2, text='Upload and Analyze', command=self.upload_and_analyze)
        self.upload_status = tk.StringVar()
        upload_status_label = ttk.Label(self.tab2, textvariable=self.upload_status)

        self.file_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.file_edit.grid(row=0, column=1, padx=5, pady=5)
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)
        self.upload_button.grid(row=1, column=0, padx=5, pady=5, sticky='w')
        upload_status_label.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky='w')

    def create_report_tab(self):
        self.report_button = ttk.Button(self.tab3, text='Generate Report', command=self.generate_report)
        self.report_log = scrolledtext.ScrolledText(self.tab3, wrap=tk.WORD)
        self.export_report_button = ttk.Button(self.tab3, text='Export Report', command=self.export_report)

        self.report_button.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.report_log.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        self.export_report_button.grid(row=2, column=1, padx=5, pady=5, sticky='w')

    def create_about_tab(self):
        about_text = """
        Developed by Dekode Security Team

        
        V.SHANMUGAM
        R.KAPILSURYA


        
        4th Year Cyber Security
        Paavai Engineering College
        """
        about_label = ttk.Label(self.tab4, text=about_text, font=('Helvetica', 14))
        about_label.grid(padx=20, pady=20)

    def create_live_ip_monitor_tab(self):
        self.ip_label = ttk.Label(self.tab5, text='Enter IP Address:')
        self.ip_edit = ttk.Entry(self.tab5)
        self.search_button = ttk.Button(self.tab5, text='Search IP Details', command=self.search_ip_details)
        self.ip_details_log = scrolledtext.ScrolledText(self.tab5, wrap=tk.WORD)

        self.ip_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.ip_edit.grid(row=0, column=1, padx=5, pady=5)
        self.search_button.grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.ip_details_log.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

    def scan(self):
        url = self.url_edit.get()
        selected_attacks = [attack for attack, var in self.attack_checkboxes.items() if var.get() == 1]
        vulnerabilities = self.check_vulnerabilities(url, selected_attacks)
        self.log_vulnerabilities(vulnerabilities)

        if 'SQL Injection' in selected_attacks:
            self.run_sqlmap(url)
        if 'XSS' in selected_attacks:
            self.run_xxs_strike(url)
        if 'WHOIS' in selected_attacks:
            self.run_see_surf(url)
        if 'CSRF' in selected_attacks:
            self.run_bolt(url)
        if 'HTTP Tampering' in selected_attacks:
            self.run_smuggler_master(url)
            

    def run_xxs_strike(self, url):
        #ADD YOUR PATH OF FILE LOCATION
        path = r'C:\Users\shanm\Project WEB PENETRATER\XSStrike-master\xsstrike.py'
        xxs_strike_command = [sys.executable, path, '-u', url]

        try:
            xxs_strike_output = subprocess.check_output(xxs_strike_command, universal_newlines=True)
            self.log_box.insert(tk.END, f'XXStrike Output:\n{xxs_strike_output}\n')
        except subprocess.CalledProcessError as e:
            self.log_box.insert(tk.END, f'Error running XXStrike: {e}\n')

    def run_sqlmap(self, url):
        #ADD YOUR PATH OF FILE LOCATION
        path = r'C:\Users\shanm\Project WEB PENETRATER\sqlmap-master\sqlmap.py'
        sqlmap_command = [sys.executable, path, '-u', url]

        try:
            sqlmap_output = subprocess.check_output(sqlmap_command, universal_newlines=True)
            self.log_box.insert(tk.END, f'SQLMap Output:\n{sqlmap_output}\n')
        except subprocess.CalledProcessError as e:
            self.log_box.insert(tk.END, f'Error running SQLMap: {e}\n')

    def run_see_surf(self, url):
        #ADD YOUR PATH OF FILE LOCATION
        path=r'C:\Users\shanm\Project WEB PENETRATER\whois\whoislookup.py'
        see_surf_command = [sys.executable, path, '-u', url]

        try:
            see_surf_output = subprocess.check_output(see_surf_command, universal_newlines=True)
            self.log_box.insert(tk.END, f'See-Surf Output:\n{see_surf_output}\n')
        except subprocess.CalledProcessError as e:
            self.log_box.insert(tk.END, f'Error running See-Surf: {e}\n')

    def run_bolt(self, url):
        #ADD YOUR PATH OF FILE LOCATION
        path1= r'C:\Users\shanm\Project WEB PENETRATER\TechViper-main\TechViper.py'
        bolt_command = ['python', path1, '-u' ,url]

        try:
            bolt_output = subprocess.check_output(bolt_command, universal_newlines=True, stderr=subprocess.STDOUT)
            self.log_box.insert(tk.END, f'bolt Master Output:\n{bolt_output}\n')
        except subprocess.CalledProcessError as e:
            self.log_box.insert(tk.END, f'Error running bolt Master: {e}\n')
            
    def run_smuggler_master(self, url):
        #ADD YOUR PATH OF FILE LOCATION
        path= r'C:\Users\shanm\\Project WEB PENETRATER\smuggler-master\smuggler-master\smuggler.py'
        smuggler_master_command = [sys.executable, path, '-u' ,url]

        try:
            smuggler_master_output = subprocess.check_output(smuggler_master_command, universal_newlines=True)
            self.log_box.insert(tk.END, f'Smuggler Master Output:\n{smuggler_master_output}\n')
        except subprocess.CalledProcessError as e:
            self.log_box.insert(tk.END, f'Error running Smuggler Master: {e}\n')

    def check_vulnerabilities(self, url, selected_attacks):
        # Existing vulnerability check logic
        vulnerabilities = [
            #Vulnerability('SQL Injection', 'High', 'This is an SQL injection vulnerability.'),
            #Vulnerability('XSS', 'Medium', 'This is a Cross-Site Scripting vulnerability.'),
        ]
        return vulnerabilities

    def log_vulnerabilities(self, vulnerabilities):
        self.log_box.delete(1.0, tk.END)
        for vuln in vulnerabilities:
            self.log_box.insert(tk.END,
                                f'Vulnerability: {vuln.name}\nSeverity: {vuln.severity}\nDescription: {vuln.description}\n\n')

    def export_log(self):
        log_text = self.log_box.get(1.0, tk.END)
        with open('vulnerability_log.txt', 'w') as log_file:
            log_file.write(log_text)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[('All Files', '*.*')])
        self.file_edit.delete(0, tk.END)
        self.file_edit.insert(0, file_path)

    def create_upload_tab(self):
        self.file_label = ttk.Label(self.tab2, text='Select File for Analysis:')
        self.file_edit = ttk.Entry(self.tab2)
        self.browse_button = ttk.Button(self.tab2, text='Browse', command=self.browse_file)
        self.upload_button = ttk.Button(self.tab2, text='Upload and Analyze', command=self.upload_and_analyze)
        self.upload_status = tk.StringVar()
        upload_status_label = ttk.Label(self.tab2, textvariable=self.upload_status)

        # ScrolledText widget to display the log for upload and analyze action
        self.upload_log = scrolledtext.ScrolledText(self.tab2, wrap=tk.WORD)

        self.file_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.file_edit.grid(row=0, column=1, padx=5, pady=5)
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)
        self.upload_button.grid(row=1, column=0, padx=5, pady=5, sticky='w')
        upload_status_label.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky='w')

        # Grid the upload log widget below the button
        self.upload_log.grid(row=2, column=0, columnspan=3, padx=5, pady=5)


    def upload_and_analyze(self):
        file_path = self.file_edit.get()

        if not file_path:
            self.upload_status.set("Please select a file to analyze.")
            return

        try:
            #ADD YOUR API KEY BELOW
            api_key = 'ADD YOUR API KEY FROM VIRUS TOTAL'

            # Upload the file to VirusTotal
            url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params = {'apikey': api_key}
            files = {'file': (file_path, open(file_path, 'rb'))}
            response = requests.post(url, files=files, params=params)

            if response.status_code == 200:
                result = response.json()
                resource = result.get('resource')

                # Check the analysis report for the uploaded file
                report_url = f'https://www.virustotal.com/gui/file/{resource}/detection'

                # Fetch the analysis report
                report_api_url = f'https://www.virustotal.com/vtapi/v2/file/report'
                report_params = {'apikey': api_key, 'resource': resource}
                report_response = requests.get(report_api_url, params=report_params)

                if report_response.status_code == 200:
                    report_data = report_response.json()
                    analysis_output = json.dumps(report_data, indent=4)
                    self.upload_log.delete(1.0, tk.END)
                    self.upload_log.insert(tk.END, analysis_output)
                    self.upload_status.set(f"File uploaded to Successfully")
                else:
                    self.upload_status.set("Error fetching the report from VirusTotal.")

            else:
                self.upload_status.set("Error uploading the file to VirusTotal.")
                self.upload_log.delete(1.0, tk.END)
                self.upload_log.insert(tk.END, "Error uploading the file to VirusTotal.")

        except Exception as e:
            self.upload_status.set(f"Check your connection / System not connected to internet")
            self.upload_log.delete(1.0, tk.END)
            self.upload_log.insert(tk.END, f"Error: {str(e)}")

    def generate_report(self):
        log_text = self.log_box.get(1.0, tk.END)
        self.report_log.delete(1.0, tk.END)
        self.report_log.insert(tk.END, log_text)

    def export_report(self):
        report_text = self.report_log.get(1.0, tk.END)
        with open('vulnerability_report.txt', 'w') as report_file:
            report_file.write(report_text)

        
    def create_url_validation_tab(self):
        self.url_validate_label = ttk.Label(self.tab6, text='Enter URL to Validate:')
        self.url_validate_edit = ttk.Entry(self.tab6)
        self.validate_button = ttk.Button(self.tab6, text='Validate URL', command=self.validate_url)
        self.validation_log = scrolledtext.ScrolledText(self.tab6, wrap=tk.WORD)
        self.validation_log.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

        self.url_validate_label.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.url_validate_edit.grid(row=0, column=2, padx=5, pady=5)
        self.validate_button.grid(row=0, column=3, padx=5, pady=5)

    def validate_url(self):
        url = self.url_validate_edit.get()

        if not url:
            self.validation_log.delete(1.0, tk.END)
            self.validation_log.insert(tk.END, 'Please enter a URL to validate.')
            return

        try:
            #ADD YOUR API KEY BELOW
            api_key = 'ADD YOUR API KEY FROM VIRUS TOTAL'

            # Check if the URL is already in the database
            url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
            url_report_params = {'apikey': api_key, 'resource': url}
            url_report_response = requests.get(url_report_url, params=url_report_params)
            url_report_data = url_report_response.json()

            if url_report_data['response_code'] == 1:
                self.validation_log.delete(1.0, tk.END)
                self.validation_log.insert(tk.END, 'This URL is already in the VirusTotal database. Here is the analysis report:\n')

                # Extract and format the report data
                report = url_report_data['verbose_msg']
                scan_results = url_report_data.get('scans', {})
                for engine, result in scan_results.items():
                    report += f"\nEngine: {engine}, Result: {result['result']}"
                
                self.validation_log.insert(tk.END, report)
            else:
                # Submit the URL for analysis
                url_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
                url_scan_params = {'apikey': api_key, 'url': url}
                url_scan_response = requests.post(url_scan_url, data=url_scan_params)
                url_scan_data = url_scan_response.json()

                if url_scan_data['response_code'] == 1:
                    self.validation_log.delete(1.0, tk.END)
                    self.validation_log.insert(tk.END, 'The URL has been successfully submitted for analysis. You can check the report later.\n')
                else:
                    self.validation_log.delete(1.0, tk.END)
                    self.validation_log.insert(tk.END, 'Error submitting the URL for analysis.\n')

        except Exception as e:
            self.validation_log.delete(1.0, tk.END)
            self.validation_log.insert(tk.END, f'Error: {str(e)}\n')

if __name__ == '__main__':
    root = tk.Tk()

    # Create a themed style for ttk widgets
    style = ThemedStyle(root)
    style.set_theme("alt")  # You can change the theme here (e.g., "clam", "alt", "plastik", etc.)

    app = VulnerabilityScanner(root)
    root.mainloop()
