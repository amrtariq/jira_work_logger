import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
from requests.auth import HTTPBasicAuth
import json
import csv
from datetime import datetime
import threading
import re

class JiraAssigneeReporter:
    def __init__(self, root):
        self.root = root
        self.root.title("Jira Assignee History CSV Generator (Enhanced)")
        self.root.geometry("650x750")
        self.root.resizable(True, True)

        # Variables
        self.jira_url = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.project_key = tk.StringVar(value="PM")
        self.start_date = tk.StringVar()
        self.end_date = tk.StringVar()

        # Set default dates (last 30 days)
        from datetime import date, timedelta
        today = date.today()
        thirty_days_ago = today - timedelta(days=30)
        self.start_date.set(thirty_days_ago.strftime("%Y-%m-%d"))
        self.end_date.set(today.strftime("%Y-%m-%d"))

        self.create_widgets()

    def extract_text_from_adf(self, adf_content):
        """Extract plain text from Atlassian Document Format (ADF)"""
        if not adf_content:
            return ""

        # If it's already a string, return it
        if isinstance(adf_content, str):
            return adf_content

        # If it's not a dict, convert to string
        if not isinstance(adf_content, dict):
            return str(adf_content)

        text_parts = []

        def extract_text_recursive(node):
            if isinstance(node, dict):
                # If this node has text, add it
                if node.get('type') == 'text' and 'text' in node:
                    text_parts.append(node['text'])

                # If this node has content, recurse into it
                if 'content' in node and isinstance(node['content'], list):
                    for child in node['content']:
                        extract_text_recursive(child)

                # Add line breaks for certain node types
                if node.get('type') == 'paragraph' and text_parts and len(text_parts) > 0:
                    if not text_parts[-1].endswith('\n'):
                        text_parts.append(' ')

            elif isinstance(node, list):
                for item in node:
                    extract_text_recursive(item)

        try:
            extract_text_recursive(adf_content)
            # Join all text parts and clean up
            result = ''.join(text_parts).strip()
            # Replace multiple spaces with single space
            while '  ' in result:
                result = result.replace('  ', ' ')
            return result
        except Exception:
            # If extraction fails, return a string representation
            return str(adf_content)[:100] + "..." if len(str(adf_content)) > 100 else str(adf_content)

    def extract_sprint_info(self, issue_fields):
        """Extract sprint information from various possible custom fields"""
        sprint_info = ""

        # Common sprint field names to check
        sprint_field_patterns = [
            'customfield_10020',  # Common Jira Cloud sprint field
            'customfield_10010',  # Another common sprint field
            'customfield_10006',  # Alternative sprint field
            'customfield_10001',  # Alternative sprint field
            'sprint'              # Sometimes it's just 'sprint'
        ]

        # Check all fields for sprint information
        for field_name, field_value in issue_fields.items():
            if field_value is None:
                continue

            # Check if this looks like a sprint field
            if 'sprint' in field_name.lower() or field_name in sprint_field_patterns:
                if isinstance(field_value, list) and len(field_value) > 0:
                    # Sprint field is usually a list, take the last (current) sprint
                    sprint_data = field_value[-1]
                    if isinstance(sprint_data, dict):
                        sprint_info = sprint_data.get('name', str(sprint_data))
                    elif isinstance(sprint_data, str):
                        # Extract sprint name from string format like "com.atlassian.greenhopper.service.sprint.Sprint@abc[id=123,rapidViewId=456,state=ACTIVE,name=Sprint 1,startDate=...]"
                        sprint_match = re.search(r'name=([^,\]]+)', sprint_data)
                        if sprint_match:
                            sprint_info = sprint_match.group(1)
                        else:
                            sprint_info = sprint_data
                elif isinstance(field_value, str):
                    sprint_match = re.search(r'name=([^,\]]+)', field_value)
                    if sprint_match:
                        sprint_info = sprint_match.group(1)
                    else:
                        sprint_info = field_value

                if sprint_info:
                    break

        return sprint_info

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="Jira Assignee History Reporter", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Instructions
        instructions = """Enhanced CSV report with assignee history, issue types, parent issues, and sprints.
For each task, shows who was assigned, when, plus issue type, parent, and sprint info.
Compatible with Jira Cloud & Server/Data Center 11.0+."""

        instructions_label = ttk.Label(main_frame, text=instructions, wraplength=600)
        instructions_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))

        # Configuration section
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="15")
        config_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        config_frame.columnconfigure(1, weight=1)

        # Jira URL
        ttk.Label(config_frame, text="Jira Server URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        jira_entry = ttk.Entry(config_frame, textvariable=self.jira_url, width=50)
        jira_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        jira_entry.insert(0, "https://originsglobal.atlassian.net")

        # Username
        ttk.Label(config_frame, text="Username/Email:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(config_frame, textvariable=self.username, width=50)
        username_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        # Password/API Token
        ttk.Label(config_frame, text="API Token/Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(config_frame, textvariable=self.password, show="*", width=50)
        password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        # Project Key
        ttk.Label(config_frame, text="Project Key:").grid(row=3, column=0, sticky=tk.W, pady=5)
        project_entry = ttk.Entry(config_frame, textvariable=self.project_key, width=50)
        project_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        # Date Range
        date_frame = ttk.Frame(config_frame)
        date_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        date_frame.columnconfigure(1, weight=1)
        date_frame.columnconfigure(3, weight=1)

        ttk.Label(date_frame, text="Start Date:").grid(row=0, column=0, sticky=tk.W)
        start_entry = ttk.Entry(date_frame, textvariable=self.start_date, width=15)
        start_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 20))

        ttk.Label(date_frame, text="End Date:").grid(row=0, column=2, sticky=tk.W)
        end_entry = ttk.Entry(date_frame, textvariable=self.end_date, width=15)
        end_entry.grid(row=0, column=3, sticky=tk.W, padx=(10, 0))

        # Generate button
        self.generate_btn = ttk.Button(main_frame, text="Generate Enhanced Report", 
                                      command=self.start_generation)
        self.generate_btn.grid(row=3, column=0, columnspan=2, pady=20)

        # Progress section
        self.progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="15")
        self.progress_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        self.progress_frame.columnconfigure(0, weight=1)

        self.progress_var = tk.StringVar(value="Ready to generate enhanced report")
        self.progress_label = ttk.Label(self.progress_frame, textvariable=self.progress_var)
        self.progress_label.grid(row=0, column=0, sticky=tk.W)

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))

        # Results section
        self.results_frame = ttk.LabelFrame(main_frame, text="Results", padding="15")
        self.results_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))
        self.results_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)

        # Results text area
        self.results_text = tk.Text(self.results_frame, height=8, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)

        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.results_frame.rowconfigure(0, weight=1)

        # Download button (initially disabled)
        self.download_btn = ttk.Button(self.results_frame, text="Save Enhanced CSV File", 
                                      command=self.save_csv, state='disabled')
        self.download_btn.grid(row=1, column=0, pady=(10, 0))

        self.report_data = []

    def start_generation(self):
        """Start report generation in a separate thread"""
        if not self.validate_inputs():
            return

        # Disable generate button and start progress
        self.generate_btn.config(state='disabled')
        self.download_btn.config(state='disabled')
        self.progress_bar.start()
        self.results_text.delete(1.0, tk.END)

        # Start generation in separate thread
        thread = threading.Thread(target=self.generate_report)
        thread.daemon = True
        thread.start()

    def validate_inputs(self):
        """Validate user inputs"""
        if not self.jira_url.get():
            messagebox.showerror("Error", "Please enter Jira Server URL")
            return False
        if not self.username.get():
            messagebox.showerror("Error", "Please enter username")
            return False
        if not self.password.get():
            messagebox.showerror("Error", "Please enter password/API token")
            return False
        if not self.project_key.get():
            messagebox.showerror("Error", "Please enter project key")
            return False

        # Validate dates
        try:
            datetime.strptime(self.start_date.get(), '%Y-%m-%d')
            datetime.strptime(self.end_date.get(), '%Y-%m-%d')
        except ValueError:
            messagebox.showerror("Error", "Please enter dates in YYYY-MM-DD format")
            return False

        return True

    def generate_report(self):
        """Generate the enhanced assignee history report"""
        try:
            self.update_progress("Connecting to Jira...")

            # Setup authentication
            auth = HTTPBasicAuth(self.username.get(), self.password.get())
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            # Build JQL query
            jql = f'project = "{self.project_key.get()}" AND created >= "{self.start_date.get()}" AND created <= "{self.end_date.get()}"'

            # Use the enhanced JQL search endpoint
            self.update_progress("Searching for issues...")
            search_url = f"{self.jira_url.get().rstrip('/')}/rest/api/3/search/jql"

            all_issues = []
            next_page_token = None
            max_results = 100

            while True:
                # Parameters for the enhanced search API - include all fields and custom fields
                params = {
                    'jql': jql,
                    'maxResults': max_results,
                    'fields': '*all',  # Get all fields including custom fields for sprint detection
                    'expand': 'changelog'
                }

                if next_page_token:
                    params['nextPageToken'] = next_page_token

                response = requests.get(search_url, headers=headers, auth=auth, 
                                       params=params, timeout=30)

                if response.status_code != 200:
                    raise Exception(f"Failed to search issues: {response.status_code} - {response.text}")

                data = response.json()
                issues = data.get('issues', [])
                all_issues.extend(issues)

                # Check for next page
                next_page_token = data.get('nextPageToken')
                if not next_page_token:
                    break

                self.update_progress(f"Found {len(all_issues)} issues so far...")

            if not all_issues:
                self.update_progress("No issues found")
                self.root.after(0, self.show_no_results)
                return

            self.update_progress(f"Processing {len(all_issues)} issues...")

            # Process each issue
            self.report_data = []

            for i, issue in enumerate(all_issues):
                try:
                    issue_key = issue['key']
                    fields = issue['fields']

                    summary = fields['summary']

                    # Extract description with ADF support
                    raw_description = fields.get('description', '')
                    description = self.extract_text_from_adf(raw_description)

                    project = fields['project']['key']

                    # Extract Issue Type
                    issue_type = fields.get('issuetype', {}).get('name', 'Unknown')

                    # Extract Parent (for subtasks)
                    parent_key = ''
                    if 'parent' in fields and fields['parent']:
                        parent_key = fields['parent'].get('key', '')

                    # Extract Sprint information
                    sprint_info = self.extract_sprint_info(fields)

                    # Process assignee changes
                    assignee_history = self.process_assignee_changes_from_issue(issue)

                    # Add to report data
                    for assignee_info in assignee_history:
                        self.report_data.append({
                            'Assignee': assignee_info['assignee'],
                            'Task Summary': summary,
                            'Details': description[:200] + '...' if len(description) > 200 else description,
                            'Project': project,
                            'Issue Key': issue_key,
                            'Type': issue_type,
                            'Parent': parent_key,
                            'Sprint': sprint_info,
                            'Start Date': assignee_info['start_date'],
                            'End Date': assignee_info['end_date']
                        })

                    if (i + 1) % 10 == 0:
                        self.update_progress(f"Processed {i + 1} of {len(all_issues)} issues...")

                except Exception as issue_error:
                    self.update_progress(f"Error processing issue {issue.get('key', 'Unknown')}: {str(issue_error)}")
                    continue

            # Update UI with results
            self.root.after(0, self.show_results)

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda msg=error_msg: self.show_error(msg))

    def process_assignee_changes_from_issue(self, issue_data):
        """Process assignee changes from issue data including changelog"""
        assignee_changes = []

        # Get all assignee changes from changelog
        changelog = issue_data.get('changelog', {})
        if 'histories' in changelog:
            for history in changelog['histories']:
                for item in history.get('items', []):
                    if item.get('field') == 'assignee':
                        assignee_changes.append({
                            'date': history['created'],
                            'from': item.get('fromString'),
                            'to': item.get('toString')
                        })

        # Sort by date
        assignee_changes.sort(key=lambda x: x['date'])

        # Build assignee periods
        assignee_periods = []

        if not assignee_changes:
            # No assignee changes, check current assignee
            current_assignee = issue_data['fields'].get('assignee')
            if current_assignee:
                assignee_name = current_assignee.get('displayName', 
                                                   current_assignee.get('name', 'Unknown'))
                assignee_periods.append({
                    'assignee': assignee_name,
                    'start_date': issue_data['fields']['created'][:10],
                    'end_date': (issue_data['fields'].get('resolutiondate', '')[:10] 
                               if issue_data['fields'].get('resolutiondate') else '')
                })
        else:
            # Process assignee changes
            for i, change in enumerate(assignee_changes):
                assignee = change['to']
                if not assignee:  # Skip null assignments
                    continue

                start_date = change['date'][:10]

                # Find end date (next change or resolution)
                if i + 1 < len(assignee_changes):
                    end_date = assignee_changes[i + 1]['date'][:10]
                else:
                    end_date = (issue_data['fields'].get('resolutiondate', '')[:10] 
                              if issue_data['fields'].get('resolutiondate') else '')

                assignee_periods.append({
                    'assignee': assignee,
                    'start_date': start_date,
                    'end_date': end_date
                })

        return assignee_periods

    def update_progress(self, message):
        def update_ui():
            self.progress_var.set(message)
        self.root.after(0, update_ui)

    def show_results(self):
        self.progress_bar.stop()
        self.generate_btn.config(state='normal')

        if self.report_data:
            results_msg = f"Enhanced report generated successfully!\n"
            results_msg += f"Total records: {len(self.report_data)}\n"
            results_msg += f"Unique issues processed: {len(set(row['Issue Key'] for row in self.report_data))}\n"
            results_msg += f"Issue types found: {len(set(row['Type'] for row in self.report_data))}\n"
            results_msg += f"Sprints found: {len(set(row['Sprint'] for row in self.report_data if row['Sprint']))}\n\n"
            results_msg += "Sample data:\n"

            # Show first few records with enhanced info
            for i, row in enumerate(self.report_data[:3]):
                results_msg += f"{i+1}. {row['Issue Key']} ({row['Type']}) - {row['Assignee']}\n"
                results_msg += f"    Dates: {row['Start Date']} to {row['End Date']}\n"
                if row['Parent']:
                    results_msg += f"    Parent: {row['Parent']}\n"
                if row['Sprint']:
                    results_msg += f"    Sprint: {row['Sprint']}\n"
                results_msg += "\n"

            if len(self.report_data) > 3:
                results_msg += f"... and {len(self.report_data) - 3} more records\n"

            self.results_text.insert(tk.END, results_msg)
            self.download_btn.config(state='normal')
            self.progress_var.set("Enhanced report ready for download")
        else:
            self.show_no_results()

    def show_no_results(self):
        self.progress_bar.stop()
        self.generate_btn.config(state='normal')
        self.results_text.insert(tk.END, "No assignee data found for the specified criteria.\n")
        self.progress_var.set("No data found")

    def show_error(self, error_msg):
        self.progress_bar.stop()
        self.generate_btn.config(state='normal')
        self.progress_var.set("Error occurred")

        error_text = f"Error: {error_msg}\n\n"
        error_text += "Please check your configuration and try again.\n"

        self.results_text.insert(tk.END, error_text)
        messagebox.showerror("Error", error_msg)

    def save_csv(self):
        if not self.report_data:
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Enhanced Assignee History Report"
        )

        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    # Enhanced fieldnames with new columns
                    fieldnames = [
                        'Assignee', 'Task Summary', 'Details', 'Project', 'Issue Key', 
                        'Type', 'Parent', 'Sprint', 'Start Date', 'End Date'
                    ]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    writer.writeheader()
                    for row in self.report_data:
                        writer.writerow(row)

                messagebox.showinfo("Success", f"Enhanced report saved successfully to:\n{filename}\n\nColumns: Assignee, Task Summary, Details, Project, Issue Key, Type, Parent, Sprint, Start Date, End Date")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

def main():
    root = tk.Tk()
    app = JiraAssigneeReporter(root)
    root.mainloop()

if __name__ == "__main__":
    main()
