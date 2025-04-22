import tkinter as tk
from tkinter import messagebox, ttk
import re
import requests
import json
import os
from datetime import datetime

class ReportApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Report System")

        # Initialize variables
        self.moderator_id = "<@299146723979427840>"
        self.report_result = ""
        self.selected_rank = "Administrator"  # Default rank
        self.webhook_url = ""  # Placeholder for Discord webhook URL
        self.reported_users_file = "reported_users.txt"  # File to store reported usernames
        self.punishment_buttons = {
            "Exploiting": ("pban W/O appeal", "Exploiting"),
            "Toxicity": ("kick warn", "Toxicity"),
            "NSFW": ("28d ban", "NSFW"),
            "Spawn Camping": ("kick warn", "Spawn Camping")
        }  # Initialize punishments with default values
        self.result = ""  # Initialize result variable
        self.punishment = ""  # Store the current punishment action
        self.punishment_label = ""  # Store the current punishment label

        # Load settings at startup
        self.load_settings()

        # Display current rank
        self.rank_label = tk.Label(root, text=f"Rank: {self.get_rank_display()}")
        self.rank_label.grid(row=0, column=0, columnspan=3)

        # Input box
        tk.Label(root, text="Paste Report Info Here:").grid(row=1, column=0, columnspan=3)
        self.input_entry = tk.Text(root, height=10, width=50)
        self.input_entry.grid(row=2, column=0, columnspan=3)

        # Punishment Buttons
        tk.Label(root, text="Select Punishment:").grid(row=3, column=0, columnspan=3)
        for i, (label, (action, _)) in enumerate(self.punishment_buttons.items()):
            tk.Button(root, text=label, command=lambda a=action, l=label: self.set_punishment(a, l)).grid(row=4, column=i)

        # Report Result Buttons
        tk.Label(root, text="Select Report Result:").grid(row=6, column=0, columnspan=3)
        tk.Button(root, text="NEF", command=lambda: self.set_result("Not Enough Evidence")).grid(row=7, column=0)
        tk.Button(root, text="Banned", command=lambda: self.set_result("Banned")).grid(row=7, column=1)
        tk.Button(root, text="Forwarded", command=lambda: self.set_result("Temp Banned and Forwarded")).grid(row=7, column=2)

        # Generate Report button
        tk.Button(root, text="Generate Report", command=self.generate_report).grid(row=8, column=1)

        # Output boxes
        self.report_output = tk.Text(root, height=10, width=50)
        self.report_output.grid(row=9, column=0, columnspan=3)

        self.ban_output = tk.Text(root, height=10, width=50)
        self.ban_output.grid(row=10, column=0, columnspan=3)

        # Ban Log Button
        tk.Button(root, text="Open Ban Log", command=self.open_ban_log).grid(row=11, column=1)

        # Settings Menu Button
        tk.Button(root, text="Settings", command=self.open_settings).grid(row=12, column=1)

        # Save settings when the window is closed
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_rank_display(self):
        rank_display_mapping = {
            "Trial Moderator": "Trial Moderator",
            "Moderator": "Moderator",
            "Admin": "Administrator"
        }
        return rank_display_mapping.get(self.selected_rank, "Rank:")

    def update_rank_label(self):
        self.rank_label.config(text=self.get_rank_display())

    def set_punishment(self, punishment, label):
        self.punishment = punishment  # Set the punishment based on the button clicked
        self.punishment_label = label  # Store the label for the ban log

    def set_result(self, result):
        self.result = result  # Set the result based on the button clicked

    def generate_report(self):
        # Get input data
        input_data = self.input_entry.get("1.0", tk.END).strip()

        # Regular expression patterns to capture the needed information
        reporter_pattern = r"Reporter\s*([\w_]+)"
        reported_pattern = r"Player Being Reported\s*([\w_]+)"
        reason_pattern = r"Reason\s*([\s\S]+?)\s*JobID:"
        jobid_pattern = r"JobID:\s*([\w-]+)"

        # Extracting information using regex
        reporter = re.search(reporter_pattern, input_data)
        reported = re.search(reported_pattern, input_data)
        reason = re.search(reason_pattern, input_data)
        job_id = re.search(jobid_pattern, input_data)

        if all([reporter, reported, reason, job_id]):
            reported_username = reported.group(1).strip()

            # Check if the user has been reported before
            if self.check_if_reported(reported_username):
                messagebox.showwarning("Previous Report Warning", f"The user '{reported_username}' has been reported before.")

            # Create formatted report log
            report_log = f"""Senior Administrator: {self.moderator_id}
Reporter: {reporter.group(1)}
Reported: {reported_username}
Reason: {reason.group(1).strip()}
Result: {self.result}
JobID: {job_id.group(1)}
"""

            # Create formatted ban log using the specified format
            ban_log = f"""Senior Administrator: {self.moderator_id}
User: {reported_username}
Reason: {self.punishment_label}
Punishment: {self.punishment}
Proof: 
"""

            # Clear previous output and insert new report log
            self.report_output.delete(1.0, tk.END)
            self.report_output.insert(tk.END, report_log)

            # Log the ban
            self.ban_output.delete(1.0, tk.END)  # Clear previous ban output
            self.ban_output.insert(tk.END, ban_log)  # Insert new ban log
            self.send_to_webhook(report_log)  # Send report log to Discord webhook

            # Add the reported username to the list if it is not already present
            self.add_reported_user(reported_username)

            # Ask if the user wants to clear the input box
            if messagebox.askyesno("Clear Input", "Do you want to clear the input box?"):
                self.input_entry.delete(1.0, tk.END)  # Clear input box if user selects Yes
        else:
            messagebox.showerror("Input Error", "Please ensure all fields are correctly filled.")

    def check_if_reported(self, username):
        if not os.path.exists(self.reported_users_file):
            return False  # File does not exist, user has not been reported

        with open(self.reported_users_file, "r") as file:
            reported_users = file.read().splitlines()
            return username in reported_users  # Check if username is in the reported users list

    def add_reported_user(self, username):
        with open(self.reported_users_file, "a") as file:
            file.write(username + "\n")  # Append new reported username to the file

    def open_ban_log(self):
        # Logic to open the ban log
        try:
            os.startfile("ban_log.txt")  # This will depend on your OS
        except Exception as e:
            messagebox.showerror("Error", f"Could not open the ban log: {e}")

    def open_settings(self):
        Settings(self)  # Create an instance of the Settings class

    def on_closing(self):
        self.save_settings()  # Save settings before closing
        self.root.destroy()  # Close the application

    def load_settings(self):
        """Load settings from a JSON file if it exists."""
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as file:
                settings = json.load(file)
                self.moderator_id = settings.get("moderator_id", self.moderator_id)
                self.selected_rank = settings.get("rank", self.selected_rank)
                self.webhook_url = settings.get("webhook_url", self.webhook_url)
                self.punishment_buttons = settings.get("punishment_buttons", self.punishment_buttons)  # Load punishments

    def save_settings(self):
        """Save current settings to a JSON file."""
        settings = {
            "moderator_id": self.moderator_id,
            "rank": self.selected_rank,
            "webhook_url": self.webhook_url,
            "punishment_buttons": self.punishment_buttons  # Save punishments
        }
        with open("settings.json", "w") as file:
            json.dump(settings, file)

    def send_to_webhook(self, report_log):
        # Your existing code to send the report log to Discord webhook
        if self.webhook_url:
            try:
                response = requests.post(self.webhook_url, json={"content": report_log})
                response.raise_for_status()  # Raise an error for bad responses
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Webhook Error", f"Could not send report to webhook: {e}")

class Settings:
    def __init__(self, report_app):
        self.report_app = report_app
        self.window = tk.Toplevel()
        self.window.title("Settings")

        # Rank
        tk.Label(self.window, text="Select Rank:").pack()
        self.rank_var = tk.StringVar(value=self.report_app.selected_rank)
        rank_options = ["Trial Moderator", "Moderator", "Admin"]
        self.rank_menu = ttk.Combobox(self.window, textvariable=self.rank_var, values=rank_options)
        self.rank_menu.pack()
        tk.Button(self.window, text="Update Rank", command=self.update_rank).pack()

        # Webhook URL
        tk.Label(self.window, text="Webhook URL:").pack()
        self.webhook_var = tk.StringVar(value=self.report_app.webhook_url)
        self.webhook_entry = tk.Entry(self.window, textvariable=self.webhook_var, width=50)
        self.webhook_entry.pack()
        tk.Button(self.window, text="Update Webhook", command=self.update_webhook).pack()

        # Moderator ID
        tk.Label(self.window, text="Moderator ID (Format: <@XXXX>):").pack()
        self.moderator_var = tk.StringVar(value=self.report_app.moderator_id[2:-1])  # Strip <@>
        self.moderator_entry = tk.Entry(self.window, textvariable=self.moderator_var, width=50)
        self.moderator_entry.pack()
        tk.Button(self.window, text="Update Moderator ID", command=self.update_moderator).pack()

        # Punishment Settings
        tk.Label(self.window, text="Manage Punishments:").pack()
        self.punishment_name_var = tk.StringVar()
        self.punishment_entry = tk.Entry(self.window, textvariable=self.punishment_name_var, width=50)
        self.punishment_entry.pack()

        self.punishment_action_var = tk.StringVar()
        self.punishment_action_entry = tk.Entry(self.window, textvariable=self.punishment_action_var, width=50)
        self.punishment_action_entry.pack()

        tk.Button(self.window, text="Add Punishment", command=self.add_punishment).pack()
        tk.Button(self.window, text="Remove Punishment", command=self.remove_punishment).pack()
        tk.Button(self.window, text="Change Punishment", command=self.change_punishment).pack()

        self.load_punishments()

    def load_punishments(self):
        for punishment, (reason, punishment_action) in self.report_app.punishment_buttons.items():
            tk.Label(self.window, text=f"{reason}: {punishment_action}").pack()

    def update_rank(self):
        new_rank = self.rank_var.get()
        self.report_app.selected_rank = new_rank
        self.report_app.save_settings()
        self.report_app.update_rank_label()
        messagebox.showinfo("Success", f"Rank updated to: {new_rank}")

    def update_webhook(self):
        new_webhook = self.webhook_var.get()
        self.report_app.webhook_url = new_webhook
        self.report_app.save_settings()
        messagebox.showinfo("Success", "Webhook URL updated.")

    def update_moderator(self):
        new_moderator = self.moderator_var.get().strip()
        # Ensure the new moderator ID is in the correct format
        if re.match(r"^\d+$", new_moderator):
            self.report_app.moderator_id = f"<@{new_moderator}>"
            self.report_app.save_settings()
            messagebox.showinfo("Success", f"Moderator ID updated to: <@{new_moderator}>")
        else:
            messagebox.showerror("Input Error", "Please enter a valid numeric moderator ID.")

    def add_punishment(self):
        punishment_name = self.punishment_name_var.get().strip()
        punishment_action = self.punishment_action_var.get().strip()

        if punishment_name and punishment_action:
            # Add the new punishment
            self.report_app.punishment_buttons[punishment_name] = (punishment_name, punishment_action)
            self.report_app.save_settings()
            self.load_punishments()  # Refresh the list
            messagebox.showinfo("Success", f"Punishment '{punishment_name}' added.")
        else:
            messagebox.showerror("Input Error", "Please enter both punishment name and action.")

    def remove_punishment(self):
        punishment_name = self.punishment_name_var.get().strip()
        if punishment_name in self.report_app.punishment_buttons:
            del self.report_app.punishment_buttons[punishment_name]
            self.report_app.save_settings()
            self.load_punishments()  # Refresh the list
            messagebox.showinfo("Success", f"Punishment '{punishment_name}' removed.")
        else:
            messagebox.showerror("Input Error", f"Punishment '{punishment_name}' not found.")

    def change_punishment(self):
        punishment_name = self.punishment_name_var.get().strip()
        punishment_action = self.punishment_action_var.get().strip()

        if punishment_name in self.report_app.punishment_buttons:
            if punishment_action:
                # Change the punishment action
                self.report_app.punishment_buttons[punishment_name] = (punishment_name, punishment_action)
                self.report_app.save_settings()
                self.load_punishments()  # Refresh the list
                messagebox.showinfo("Success", f"Punishment '{punishment_name}' updated.")
            else:
                messagebox.showerror("Input Error", "Please enter a new punishment action.")
        else:
            messagebox.showerror("Input Error", f"Punishment '{punishment_name}' not found.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ReportApp(root)
    root.mainloop()
