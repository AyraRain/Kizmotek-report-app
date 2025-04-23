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
        self.result = ""  # Initialize result variable
        self.punishment = ""  # Store the current punishment action
        self.punishment_label = ""  # Store the current punishment label
        self.dark_mode_enabled = tk.BooleanVar(value=False)  # Initialize dark mode state

        # Default punishment buttons
        self.punishment_buttons = {
            "Toxicity": ("Warned / 1d ban", None),
            "Spawn Camping": ("Warned / 1d ban", None),
            "Exploiting": ("pban w/o appeal", None),
            "NSFW": ("30d", None),
        }

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
        self.create_punishment_buttons()

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

    def create_punishment_buttons(self):
        """Create punishment buttons dynamically."""
        for i, (label, (action, button)) in enumerate(self.punishment_buttons.items()):
            if button is None:  # Only create the button if it doesn't already exist
                button = tk.Button(
                    self.root,
                    text=label,
                    command=lambda a=action, l=label: self.set_punishment(a, l)
                )
                button.place(x=10 + i * 100, y=80)  # Default position
                self.punishment_buttons[label] = (action, button)

    def set_punishment(self, punishment, label):
        self.punishment = punishment  # Set the punishment based on the button clicked
        self.punishment_label = label  # Store the label for the ban log

    def set_result(self, result):
        """Set the result based on the button clicked."""
        self.result = result

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
                dark_mode = settings.get("dark_mode", False)  # Load dark mode state
                self.apply_dark_mode(dark_mode)  # Apply dark mode
                self.dark_mode_enabled.set(dark_mode)  # Initialize variable

                # Update punishment buttons without duplicating
                for label, data in settings.get("punishment_buttons", {}).items():
                    action = data.get("action", "")
                    position = data.get("position", None)

                    # Check if the button already exists in the dictionary
                    if label in self.punishment_buttons:
                        _, button = self.punishment_buttons[label]
                        if button is None:
                            # Create a new button if the reference is None
                            button = tk.Button(
                                self.root,
                                text=label,
                                command=lambda a=action, l=label: self.set_punishment(a, l)
                            )
                            self.punishment_buttons[label] = (action, button)
                        if position:
                            button.place(x=position[0], y=position[1])  # Update position
                    else:
                        # Create a new button if it doesn't exist
                        new_button = tk.Button(
                            self.root,
                            text=label,
                            command=lambda a=action, l=label: self.set_punishment(a, l)
                        )
                        if position:
                            new_button.place(x=position[0], y=position[1])
                        self.punishment_buttons[label] = (action, new_button)

    def save_settings(self):
        """Save current settings to a JSON file."""
        settings = {
            "moderator_id": self.moderator_id,
            "rank": self.selected_rank,
            "webhook_url": self.webhook_url,
            "dark_mode": self.dark_mode_enabled.get(),
            "punishment_buttons": {
                k: {
                    "action": v[0],
                    "position": (v[1].winfo_x(), v[1].winfo_y()) if isinstance(v[1], tk.Button) else None
                }
                for k, v in self.punishment_buttons.items() if v[1] is not None  # Only save existing buttons
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

    def apply_dark_mode(self, enable):
        """Apply dark mode to the application."""
        bg_color = "#2E2E2E" if enable else "#F0F0F0"
        fg_color = "#FFFFFF" if enable else "#000000"

        # Update the root window
        self.root.configure(bg=bg_color)

        # Update all widgets
        for widget in self.root.winfo_children():
            if isinstance(widget, (tk.Label, tk.Button, tk.Text)):
                widget.configure(bg=bg_color, fg=fg_color)
            if isinstance(widget, tk.Text):
                widget.configure(insertbackground=fg_color)  # Cursor color for Text widgets


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

        # Webhook URL
        tk.Label(self.window, text="Webhook URL:").pack()
        self.webhook_var = tk.StringVar(value=self.report_app.webhook_url)
        self.webhook_entry = tk.Entry(self.window, textvariable=self.webhook_var, width=50)
        self.webhook_entry.pack()
        tk.Button(self.window, text="Update Webhook", command=self.update_webhook).pack()

        # Moderator ID
        tk.Label(self.window, text="Moderator ID:").pack()
        self.moderator_var = tk.StringVar(value=self.report_app.moderator_id[2:-1])  # Strip <@>
        self.moderator_entry = tk.Entry(self.window, textvariable=self.moderator_var, width=50)
        self.moderator_entry.pack()
        tk.Button(self.window, text="Update Moderator ID", command=self.update_moderator).pack()

        # Punishment Management
        tk.Label(self.window, text="Manage Punishments:").pack()
        self.manage_punishment_var = tk.StringVar()
        self.manage_punishment_menu = ttk.Combobox(
            self.window,
            textvariable=self.manage_punishment_var,
            values=list(self.report_app.punishment_buttons.keys())
        )
        self.manage_punishment_menu.pack()

        # Entry for new action or name
        tk.Label(self.window, text="New Value:").pack()
        self.new_value_var = tk.StringVar()
        self.new_value_entry = tk.Entry(self.window, textvariable=self.new_value_var)
        self.new_value_entry.pack()

        # Buttons for updating or deleting punishments
        tk.Button(self.window, text="Update Punishment", command=self.update_punishment).pack()
        tk.Button(self.window, text="Delete Punishment", command=self.delete_punishment).pack()

        # Add New Punishment
        tk.Label(self.window, text="Punishment Name:").pack()
        self.new_punishment_name_var = tk.StringVar()
        self.new_punishment_name_entry = tk.Entry(self.window, textvariable=self.new_punishment_name_var)
        self.new_punishment_name_entry.pack()
        tk.Label(self.window, text="Punishment Action:").pack()
        self.new_punishment_action_var = tk.StringVar()
        self.new_punishment_action_entry = tk.Entry(self.window, textvariable=self.new_punishment_action_var)
        self.new_punishment_action_entry.pack()
        tk.Button(self.window, text="Add Punishment", command=self.add_punishment).pack()

        # Drag-and-Drop Toggle
        tk.Label(self.window, text="Drag and Drop Punishment Buttons:").pack()
        self.drag_enabled = tk.BooleanVar(value=False)
        tk.Checkbutton(self.window, text="Enable", variable=self.drag_enabled, command=self.toggle_drag).pack()

        # Save and Restore Button Positions
        tk.Button(self.window, text="Save Button Positions", command=self.save_button_positions).pack()
        tk.Button(self.window, text="Restore Button Positions", command=self.restore_button_positions).pack()

        # Dark Mode Toggle
        tk.Label(self.window, text="Dark Mode:").pack()
        self.dark_mode_enabled = tk.BooleanVar(value=self.report_app.dark_mode_enabled.get())
        tk.Checkbutton(self.window, text="Enable", variable=self.dark_mode_enabled, command=self.toggle_dark_mode).pack()

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

    def add_punishment(self):
        punishment_name = self.new_punishment_name_var.get()
        punishment_action = self.new_punishment_action_var.get()
        if punishment_name and punishment_action:
            # Add the punishment to the dictionary
            self.report_app.punishment_buttons[punishment_name] = (punishment_action, None)

            # Create a new button for the punishment
            new_button = tk.Button(
                self.report_app.root,
                text=punishment_name,
                command=lambda a=punishment_action, l=punishment_name: self.report_app.set_punishment(a, l)
            )
            # Place the button dynamically (e.g., below existing buttons)
            button_count = len(self.report_app.punishment_buttons)
            new_button.place(x=10 + (button_count - 1) * 100, y=80)  # Adjust x and y as needed

            # Update the punishment_buttons dictionary with the button reference
            self.report_app.punishment_buttons[punishment_name] = (punishment_action, new_button)

            # Save the updated punishments
            self.report_app.save_settings()
            messagebox.showinfo("Punishment Added", f"Punishment '{punishment_name}' added successfully!")
        else:
            messagebox.showerror("Input Error", "Please fill out both fields for the punishment.")

    def update_punishment(self):
        selected_punishment = self.manage_punishment_var.get()
        new_value = self.new_value_var.get()
        if selected_punishment and new_value:
            if selected_punishment in self.report_app.punishment_buttons:
                # Update the punishment action
                action, button = self.report_app.punishment_buttons[selected_punishment]
                self.report_app.punishment_buttons[selected_punishment] = (new_value, button)
                self.report_app.save_settings()
                messagebox.showinfo("Punishment Updated", f"Punishment '{selected_punishment}' updated successfully!")
            else:
                messagebox.showerror("Error", "Selected punishment does not exist.")
        else:
            messagebox.showerror("Input Error", "Please select a punishment and provide a new value.")

    def delete_punishment(self):
        punishment_name = self.manage_punishment_var.get()
        if punishment_name in self.report_app.punishment_buttons:
            # Remove the button from the GUI
            _, button = self.report_app.punishment_buttons[punishment_name]
            if button:
                button.destroy()
            # Remove the punishment from the dictionary
            del self.report_app.punishment_buttons[punishment_name]
            # Save the updated punishments to settings
            self.report_app.save_settings()
            messagebox.showinfo("Punishment Deleted", f"Punishment '{punishment_name}' deleted successfully!")
        else:
            messagebox.showerror("Error", "Punishment not found.")

    def toggle_drag(self):
        """Enable or disable drag-and-drop functionality."""
        if self.drag_enabled.get():
            for label, (_, button) in self.report_app.punishment_buttons.items():
                if button and not hasattr(button, "drag_enabled"):  # Check if drag is already enabled
                    button.bind("<Button-1>", self.start_drag)
                    button.bind("<B1-Motion>", self.drag)
                    button.bind("<ButtonRelease-1>", self.stop_drag)
                    button.drag_enabled = True  # Mark the button as having drag enabled
        else:
            for label, (_, button) in self.report_app.punishment_buttons.items():
                if button and hasattr(button, "drag_enabled"):  # Check if drag was enabled
                    button.unbind("<Button-1>")
                    button.unbind("<B1-Motion>")
                    button.unbind("<ButtonRelease-1>")
                    del button.drag_enabled  # Remove the drag-enabled flag

    def start_drag(self, event):
        """Start dragging a button."""
        self.dragging_button = event.widget
        self.start_x = event.x

    def drag(self, event):
        """Handle dragging of a button."""
        if self.dragging_button:
            dx = event.x - self.start_x
            current_x = self.dragging_button.winfo_x()
            new_x = current_x + dx
            # Constrain the button's movement within the window's width
            if new_x < 0:
                new_x = 0
            elif new_x + self.dragging_button.winfo_width() > self.dragging_button.winfo_toplevel().winfo_width():
                new_x = self.dragging_button.winfo_toplevel().winfo_width() - self.dragging_button.winfo_width()
            self.dragging_button.place(x=new_x)

    def stop_drag(self, event):
        """Stop dragging and save the new position."""
        if self.dragging_button:
            # Find the label of the dragged button
            for label, (action, button) in self.report_app.punishment_buttons.items():
                if button == self.dragging_button:
                    # Update the position in the punishment_buttons dictionary
                    new_x = self.dragging_button.winfo_x()
                    new_y = self.dragging_button.winfo_y()
                    self.report_app.punishment_buttons[label] = (action, self.dragging_button)

                    # Save the new position to settings
                    self.report_app.save_settings()
                    break
        self.dragging_button = None

    def save_button_positions(self):
        """Manually save the positions of the buttons."""
        self.report_app.save_settings()
        messagebox.showinfo("Save Positions", "Button positions have been saved successfully.")

    def restore_button_positions(self):
        """Restore the positions of the buttons from the settings."""
        self.report_app.load_settings()
        messagebox.showinfo("Restore Positions", "Button positions have been restored successfully.")

    def toggle_dark_mode(self):
        """Toggle dark mode on or off."""
        self.report_app.apply_dark_mode(self.dark_mode_enabled.get())
        self.report_app.save_settings()  # Save the dark mode state


if __name__ == "__main__":
    root = tk.Tk()
    app = ReportApp(root)
    root.mainloop()
