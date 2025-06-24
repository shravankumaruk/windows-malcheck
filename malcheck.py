import psutil
import platform
import tkinter as tk
from tkinter import ttk, messagebox, Menu, filedialog
import webbrowser
import os
import hashlib
import requests
import csv
from threading import Thread

# Your VirusTotal API key
API_KEY = 'YOUR_API_KEY'
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"

# Function to calculate the SHA-256 hash of a file
def get_file_hash(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None

# Function to get VirusTotal report for a file hash
def get_virustotal_report(file_hash):
    url = f"{VT_BASE_URL}/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious_count = last_analysis_stats.get("malicious", 0)
            if malicious_count > 0:
                return f"Detected ({malicious_count})"
            else:
                return "No threats"
        elif response.status_code == 403:
            return "API Key is invalid or insufficient permissions"
        else:
            return "Not found"
    except Exception as e:
        return "Error"

# Function to refresh the process list
def refresh_process_list():
    for row in tree.get_children():
        tree.delete(row)

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe_path = proc.info['exe']
            priority = proc.nice()  # Get the process priority
            # Insert into the treeview
            tree.insert("", "end", values=(pid, name, priority, exe_path))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Ignore processes that can't be accessed or no longer exist

# Function to kill selected process
def kill_process():
    selected_item = tree.selection()
    if selected_item:
        pid = tree.item(selected_item)['values'][0]
        name = tree.item(selected_item)['values'][1]
        try:
            proc = psutil.Process(pid)
            proc.terminate()  # Terminate process (soft kill)
            messagebox.showinfo("Success", f"Process '{name}' with PID {pid} has been terminated.")
            refresh_process_list()
        except psutil.AccessDenied:
            messagebox.showerror("Error", f"Access Denied! You need admin rights to terminate PID {pid}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Function to open the file location of a process
def open_file_location():
    selected_item = tree.selection()
    if selected_item:
        exe_path = tree.item(selected_item)['values'][3]
        if exe_path:
            os.startfile(os.path.dirname(exe_path))  # Open the folder where the exe is located

# Function to search process name online
def search_online():
    selected_item = tree.selection()
    if selected_item:
        process_name = tree.item(selected_item)['values'][1]
        if process_name:
            webbrowser.open(f"https://www.google.com/search?q={process_name}")

# Function to view the VirusTotal result online
def view_in_virustotal():
    selected_item = tree.selection()
    if selected_item:
        exe_path = tree.item(selected_item)['values'][3]
        if exe_path:
            # Get file hash and check VirusTotal
            file_hash = get_file_hash(exe_path)
            if file_hash:
                # Start the loading dialog in a separate thread
                loading_popup = tk.Toplevel(root)
                loading_popup.title("Loading")
                tk.Label(loading_popup, text="Loading VirusTotal results, please wait...").pack(padx=20, pady=20)
                loading_popup.geometry("300x100")
                loading_popup.grab_set()  # Make it modal
                loading_popup.update()  # Update the loading popup

                # Run the VirusTotal check in a separate thread
                def check_virustotal():
                    vt_status = get_virustotal_report(file_hash)
                    loading_popup.destroy()  # Close the loading dialog
                    show_virustotal_popup(exe_path, file_hash, vt_status)

                Thread(target=check_virustotal).start()

def show_virustotal_popup(exe_path, file_hash, vt_status):
    popup = tk.Toplevel()
    popup.title("VirusTotal Result")
    msg = f"File: {exe_path}\nHash: {file_hash}\nVirusTotal Status: {vt_status}"

    label = tk.Label(popup, text=msg, padx=20, pady=20)
    label.pack()

    button_frame = tk.Frame(popup)
    button_frame.pack(pady=10)

    okay_button = tk.Button(button_frame, text="Okay", command=popup.destroy)
    okay_button.grid(row=0, column=0, padx=10)

    more_details_button = tk.Button(button_frame, text="More Details",
                                    command=lambda: webbrowser.open(f"https://www.virustotal.com/gui/file/{file_hash}"))
    more_details_button.grid(row=0, column=1, padx=10)

# Function to save the process list to a CSV file
def save_to_csv():
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['PID', 'Name', 'Priority', 'Executable Path'])  # Header
            for row in tree.get_children():
                writer.writerow(tree.item(row)['values'])  # Write each row's values
        messagebox.showinfo("Success", "Process list saved successfully!")  # Success message

# Function to show system information
def show_system_info():
    sys_info = f"System: {platform.system()}\n" \
               f"Node Name: {platform.node()}\n" \
               f"Release: {platform.release()}\n" \
               f"Version: {platform.version()}\n" \
               f"Machine: {platform.machine()}\n" \
               f"Processor: {platform.processor()}\n" \
               f"RAM: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB"  # Convert to GB
    messagebox.showinfo("System Information", sys_info)

# Function to show the About popup
def show_about():
    messagebox.showinfo("About", "This application was built and developed by Shravan Kumar UK")

# Function to open the update URL
def open_update_url():
    webbrowser.open("https://shravanprojects.github.io/windows-malcheck/")

# Function to show search dialog
def show_search_dialog(event=None):
    search_popup = tk.Toplevel(root)
    search_popup.title("Search Process")

    tk.Label(search_popup, text="Enter process name:").pack(padx=80, pady=10)
    search_entry = tk.Entry(search_popup)
    search_entry.pack(padx=10, pady=10)

    def search_process():
        search_term = search_entry.get().strip().lower()
        for row in tree.get_children():
            tree.delete(row)  # Clear the treeview
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'].lower()
                exe_path = proc.info['exe']
                priority = proc.nice()  # Get the process priority
                if search_term in name:
                    tree.insert("", "end", values=(pid, proc.info['name'], priority, exe_path))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass  # Ignore processes that can't be accessed or no longer exist

    tk.Button(search_popup, text="Search", command=search_process).pack(pady=10)
    search_popup.bind('<Return>', lambda e: search_process())  # Allow pressing Enter to search

# Function to open Windows License
def open_windows_license():
    os.system("winver")  # Opens the Windows version information dialog

# Create the main window
root = tk.Tk()
root.title("Windows Malcheck")

# Create a menu bar
menu_bar = Menu(root)
root.config(menu=menu_bar)

# Add menu options
file_menu = Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Save", command=save_to_csv)
menu_bar.add_cascade(label="File", menu=file_menu)

# More options
more_menu = Menu(menu_bar, tearoff=0)
more_menu.add_command(label="Windows License", command=open_windows_license)  # Added Windows License option
more_menu.add_command(label="About", command=show_about)
more_menu.add_command(label="Update", command=open_update_url)
menu_bar.add_cascade(label="More", menu=more_menu)

# Create the process list display (Treeview)
columns = ('PID', 'Name', 'Priority', 'Executable Path')
tree = ttk.Treeview(root, columns=columns, show='headings', height=15)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="center")  # Center the text in each column

# Create a scrollbar
scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side='right', fill='y')

tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Bind right-click event to show context menu
context_menu = Menu(root, tearoff=0)
context_menu.add_command(label="Open File Location", command=open_file_location)
context_menu.add_command(label="Search Online", command=search_online)
context_menu.add_command(label="Check VirusTotal", command=view_in_virustotal)

def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)

tree.bind("<Button-3>", show_context_menu)  # Right-click to show menu

# Add buttons for refresh, kill, and system information
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

refresh_button = tk.Button(button_frame, text="Refresh", command=refresh_process_list)
refresh_button.grid(row=0, column=0, padx=10)

kill_button = tk.Button(button_frame, text="Kill", command=kill_process)
kill_button.grid(row=0, column=1, padx=10)

system_info_button = tk.Button(button_frame, text="System Information", command=show_system_info)
system_info_button.grid(row=0, column=2, padx=10)  # Added button for system info

# Bind Ctrl+F to show search dialog
root.bind('<Control-f>', show_search_dialog)

# Initial refresh of process list
refresh_process_list()

# Run the application
root.mainloop()
