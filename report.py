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

        # Set minimum window size to ensure all elements are visible
        self.root.minsize(600, 900)  # Adjust height to fit all buttons and output boxes

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
        self.rank_label.place(x=10, y=10)  # Use absolute positioning for the rank label

        # Input box
        tk.Label(root, text="Paste Report Info Here:").place(x=10, y=250)
        self.input_entry = tk.Text(root, height=10, width=50)
        self.input_entry.place(x=10, y=280)

        # Punishment Buttons
        tk.Label(root, text="Select Punishment:").place(x=10, y=50)  # Use absolute positioning for the label
        for i, (label, (action, _)) in enumerate(self.punishment_buttons.items()):
            button = tk.Button(self.root, text=label, command=lambda a=action, l=label: self.set_punishment(a, l))
            button.place(x=10 + i * 100, y=80)  # Default position
            self.punishment_buttons[label] = (action, button)

        # Report Result Buttons
        tk.Label(root, text="Select Report Result:").place(x=10, y=150)  # Use absolute positioning for the label
        tk.Button(root, text="NEF", command=lambda: self.set_result("Not Enough Evidence")).place(x=10, y=180)
        tk.Button(root, text="Banned", command=lambda: self.set_result("Banned")).place(x=110, y=180)
        tk.Button(root, text="Forwarded", command=lambda: self.set_result("Temp Banned and Forwarded")).place(x=210, y=180)

        # Generate Report button
        tk.Button(root, text="Generate Report", command=self.generate_report).place(x=155, y=450)  # Adjusted position

        # Output boxes
        self.report_output = tk.Text(root, height=10, width=50)
        self.report_output.place(x=10, y=500)

        self.ban_output = tk.Text(root, height=10, width=50)
        self.ban_output.place(x=10, y=650)

        # Ban Log Button
        tk.Button(root, text="Open Ban Log", command=self.open_ban_log).place(x=10, y=820)

        # Settings Menu Button
        tk.Button(root, text="Settings", command=self.open_settings).place(x=110, y=820)

        # Print current rank button (next to settings button)
        tk.Button(root, text="Print Current Rank", command=self.print_current_rank).place(x=210, y=820)

        # Save settings when the window is closed
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_rank_display(self):
        rank_display_mapping = {
            "Trial Moderator": "Trial Moderator",
            "Moderator": "Moderator",
            "Admin": "Administrator",
            "Senior Administrator": "Senior Administrator"  # Add Senior Administrator here
        }
        return rank_display_mapping.get(self.selected_rank, "Rank: ")

    def update_rank_label(self):
        self.rank_label.config(text=f"Rank: {self.get_rank_display()}")

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

            # Create formatted report log with dynamic rank based on selected rank
            rank_display = self.get_rank_display()  # Always fetch the updated rank
            report_log = f"""
{rank_display}: {self.moderator_id}
Reporter: {reporter.group(1)}
Reported: {reported_username}
Reason: {reason.group(1).strip()}
Result: {self.result}
JobID: {job_id.group(1)}
"""

            # Create formatted ban log using the specified format
            ban_log = f"""
{rank_display}: {self.moderator_id}
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
            return username in reported_users  # Check if username is in reported users list

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
                for label, data in settings.get("punishment_buttons", {}).items():
                    if label in self.punishment_buttons:
                        action = data.get("action", self.punishment_buttons[label][0])
                        position = data.get("position", None)
                        button = self.punishment_buttons[label][1]

                        # Ensure the button reference is preserved
                        if isinstance(button, tk.Button):
                            self.punishment_buttons[label] = (action, button)

                            # Restore button position if available
                            if position:
                                button.place(x=position[0], y=position[1])

    def save_settings(self):
        """Save current settings to a JSON file."""
        settings = {
            "moderator_id": self.moderator_id,
            "rank": self.selected_rank,
            "webhook_url": self.webhook_url,
            "punishment_buttons": {
                k: {
                    "action": v[0],
                    "position": (v[1].winfo_x(), v[1].winfo_y()) if isinstance(v[1], tk.Button) else None
                }
                for k, v in self.punishment_buttons.items()
            }
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

    def print_current_rank(self):
        # Display the current rank in a message box
        messagebox.showinfo("Current Rank", f"The current rank is: {self.get_rank_display()}")


class Settings:
    def __init__(self, report_app):
        self.report_app = report_app
        self.window = tk.Toplevel()
        self.window.title("Settings")

        # Rank
        tk.Label(self.window, text="Select Rank:").pack()
        self.rank_var = tk.StringVar(value=self.report_app.selected_rank)
        rank_options = ["Trial Moderator", "Moderator", "Admin", "Senior Administrator"]
        self.rank_menu = ttk.Combobox(self.window, textvariable=self.rank_var, values=rank_options)
        self.rank_menu.pack()
        tk.Button(self.window, text="Update Rank", command=self.update_rank).pack()

        # Print current rank button in settings
        tk.Button(self.window, text="Print Current Rank", command=self.print_current_rank).pack()

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
        self.punishment_action_var = tk.StringVar()

        tk.Label(self.window, text="Punishment Name:").pack()
        self.punishment_name_entry = tk.Entry(self.window, textvariable=self.punishment_name_var)
        self.punishment_name_entry.pack()

        tk.Label(self.window, text="Punishment Action:").pack()
        self.punishment_action_entry = tk.Entry(self.window, textvariable=self.punishment_action_var)
        self.punishment_action_entry.pack()

        tk.Button(self.window, text="Save Punishment", command=self.save_punishment).pack()

        # Drag-and-Drop Toggle
        tk.Label(self.window, text="Drag and Drop Punishment Buttons:").pack()
        self.drag_enabled = tk.BooleanVar(value=False)
        tk.Checkbutton(self.window, text="Enable", variable=self.drag_enabled, command=self.toggle_drag).pack()

        # Save and Restore Button Positions
        tk.Button(self.window, text="Save Button Positions", command=self.save_button_positions).pack()
        tk.Button(self.window, text="Restore Button Positions", command=self.restore_button_positions).pack()

    def save_button_positions(self):
        """Manually save the positions of the buttons."""
        self.report_app.save_settings()
        messagebox.showinfo("Save Positions", "Button positions have been saved successfully.")

    def restore_button_positions(self):
        """Restore the positions of the buttons from the settings."""
        self.report_app.load_settings()
        messagebox.showinfo("Restore Positions", "Button positions have been restored successfully.")

    def toggle_drag(self):
        """Enable or disable drag-and-drop functionality."""
        if self.drag_enabled.get():
            for label, (_, button) in self.report_app.punishment_buttons.items():
                if button:
                    button.bind("<Button-1>", self.start_drag)
                    button.bind("<B1-Motion>", self.drag)
                    button.bind("<ButtonRelease-1>", self.stop_drag)
        else:
            for label, (_, button) in self.report_app.punishment_buttons.items():
                if button:
                    button.unbind("<Button-1>")
                    button.unbind("<B1-Motion>")
                    button.unbind("<ButtonRelease-1>")

    def start_drag(self, event):
        """Start dragging a button."""
        self.dragging_button = event.widget
        self.start_x = event.x

    def drag(self, event):
        """Handle dragging of a button (restricted to x-axis and within section boundaries)."""
        if self.dragging_button:
            dx = event.x - self.start_x
            current_x = self.dragging_button.winfo_x()
            new_x = current_x + dx

            # Get the window's width and the button's width
            window_width = self.dragging_button.winfo_toplevel().winfo_width()
            button_width = self.dragging_button.winfo_width()

            # Constrain the button's movement within the window's width
            if new_x < 0:
                new_x = 0  # Prevent moving beyond the left edge
            elif new_x + button_width > window_width:
                new_x = window_width - button_width  # Prevent moving beyond the right edge

            # Get the button's current y-coordinate
            current_y = self.dragging_button.winfo_y()

            # Enforce vertical boundaries for punishment and report sections
            if 280 <= current_y <= 320:  # Punishment section row
                new_y = 280
            elif 400 <= current_y <= 440:  # Report section row
                new_y = 400
            else:
                new_y = current_y  # Keep the button in its current row if it's not in a valid section

            # Enforce horizontal spacing between buttons
            for label, (_, button) in self.report_app.punishment_buttons.items():
                if button and button != self.dragging_button:
                    other_x = button.winfo_x()
                    other_width = button.winfo_width()

                    # Prevent overlap by ensuring a minimum spacing of 10 pixels
                    if abs(new_x - other_x) < button_width + 10:
                        if new_x > other_x:
                            new_x = other_x + other_width + 10
                        else:
                            new_x = other_x - button_width - 10

            # Update the button's position
            self.dragging_button.place(x=new_x, y=new_y)

    def stop_drag(self, event):
        """Stop dragging and save the new position."""
        self.dragging_button = None

    def update_rank(self):
        new_rank = self.rank_var.get()
        self.report_app.selected_rank = new_rank
        self.report_app.update_rank_label()  # Update the rank label in the main app
        self.report_app.save_settings()  # Save the new rank
        messagebox.showinfo("Rank Updated", f"Rank updated to {new_rank}")

    def update_webhook(self):
        new_webhook = self.webhook_var.get()
        self.report_app.webhook_url = new_webhook
        self.report_app.save_settings()  # Save the new webhook
        messagebox.showinfo("Webhook Updated", "Webhook URL updated successfully")

    def update_moderator(self):
        new_moderator_id = "<@" + self.moderator_var.get() + ">"  # Format moderator ID correctly
        self.report_app.moderator_id = new_moderator_id
        self.report_app.save_settings()  # Save the new moderator ID
        messagebox.showinfo("Moderator ID Updated", f"Moderator ID updated to {new_moderator_id}")

    def save_punishment(self):
        punishment_name = self.punishment_name_var.get()
        punishment_action = self.punishment_action_var.get()

        if punishment_name and punishment_action:
            self.report_app.punishment_buttons[punishment_name] = (punishment_action, None)
            self.report_app.save_settings()  # Save the updated punishments
            messagebox.showinfo("Punishment Saved", "Punishment updated successfully")
        else:
            messagebox.showerror("Input Error", "Please fill out both fields for punishment.")

    def print_current_rank(self):
        # Display the current rank in a message box
        messagebox.showinfo("Current Rank", f"The current rank is: {self.report_app.get_rank_display()}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ReportApp(root)
    root.mainloop()
