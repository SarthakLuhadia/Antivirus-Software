import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import requests
import json
import os
from cryptography.fernet import Fernet
import schedule
import time
import requests

selected_file = None
selected_folder = None

def scan_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": (file_path, open(file_path, "rb"), "application/octet-stream")}
    headers = {"accept": "application/json", "x-apikey": "6b96af9709b7f9d513e808f9fa0a94b01282b15b548e61d63453e204aa60da0d"}
    response = requests.post(url, files=files, headers=headers)
    response_dict = json.loads(response.text)
    url = response_dict["data"]["links"]["self"]
    response_data = requests.get(url, headers=headers)
    result1 = json.loads(response_data.text)
    scan1 = result1["data"]["attributes"]["stats"]["malicious"]
    scan2 = result1["data"]["attributes"]["stats"]["harmless"]
    scan3 = result1["data"]["attributes"]["stats"]["type-unsupported"]
    if int(scan1) > 0:
        return 1
    elif scan1 + scan2 + scan3 == 0:
        return 2
    else:
        return 0

# Function to scan a folder for viruses
def scan_folder(selected_folder):
    infected_files = []
    for root, dirs, files in os.walk(selected_folder):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_file(file_path)
            if result == 1:
                infected_files.append(file_path)
    return infected_files


def scan_url(url):
    api_key = "6b96af9709b7f9d513e808f9fa0a94b01282b15b548e61d63453e204aa60da0d"
    url = f"https://www.virustotal.com/api/v3/urls/{url}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        scan_date = result["data"]["attributes"]["last_analysis_date"]
        scan_results = result["data"]["attributes"]["last_analysis_stats"]
        return scan_date, scan_results
    else:
        return None, None

def scan_url_command():
    url = url_entry.get()
    if url:
        scan_date, scan_results = scan_url(url)
        if scan_date and scan_results:
            if scan_results["malicious"] > 0 or scan_results["suspicious"] > 0:
                result_text = f"Caution: This URL may be unsafe.\nScan Date: {scan_date}\nResults: {scan_results}"
            else:
                result_text = f"Safe to browse!\nScan Date: {scan_date}\nResults: {scan_results}"

            messagebox.showinfo("URL Scan Result", result_text)
        else:
            messagebox.showinfo("URL Scan Failed", "Unable to retrieve scan results.")
    else:
        messagebox.showinfo("Input Error", "Please enter a URL to scan.")


def select_file():
    global selected_file
    filepath = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if filepath:
        selected_file = filepath
        file_label.config(text="Selected File: " + selected_file)
        scan_file_button.config(state=tk.NORMAL)

def select_folder():
    global selected_folder
    folderpath = filedialog.askdirectory()
    if folderpath:
        selected_folder = folderpath
        folder_label.config(text="Selected Folder: " + selected_folder)
        scan_folder_button.config(state=tk.NORMAL)


# Encryption Functions
def generate_key():
    return Fernet.generate_key()

def write_key_to_file(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        return key_file.read()

def encrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
def scan_file_command():
    progress_label.config(text="Scanning for Viruses...")
    result = scan_file(selected_file)
    progress_label.config(text="Scan Complete")
    if result == 1:
        popup = tk.Tk()
        popup.title("Virus Detected")
        popup.geometry("300x150")
        label = tk.Label(popup, text="Virus found in the selected file.", font=("Arial", 12))
        label.pack(pady=10)

        def delete_action():
            delete_file()
            popup.destroy()

        def isolate_action():
            key = generate_key()
            write_key_to_file(key, 'encryption_key.key')
            encrypt_file(load_key_from_file('encryption_key.key'), selected_file, selected_file + '.encrypted')
            os.remove(selected_file)
            messagebox.showinfo("File Isolated", "The file has been encrypted and isolated.")
            popup.destroy()

        def no_action():
            popup.destroy()

        delete_button = tk.Button(popup, text="Delete File", command=delete_action, font=("Arial", 12))
        delete_button.pack(pady=(10, 20))
        isolate_button = tk.Button(popup, text="Isolate (Encrypt)", command=isolate_action, font=("Arial", 12))
        isolate_button.pack(pady=(0, 20))
        no_button = tk.Button(popup, text="No Action", command=no_action, font=("Arial", 12))
        no_button.pack(pady=(0, 10))

        popup.mainloop()
    elif result == 2:
        messagebox.showinfo("Scan Failed", "Try again.")
    else:
        messagebox.showinfo("Scan Complete", "No viruses found in the selected file.")


def scan_folder_command():
    global selected_folder
    progress_label.config(text="Scanning for Viruses...")
    infected_files = scan_folder(selected_folder)
    progress_label.config(text="Scan Complete")
    if infected_files:
        choice = messagebox.askyesno("Virus Found", f"{len(infected_files)} infected files found. Would you like to delete them?")
        if choice:
            for file_path in infected_files:
                os.remove(file_path)
            messagebox.showinfo("Files Deleted", "Infected files have been deleted.")
            selected_folder = None
            folder_label.config(text="Selected Folder: None")
            scan_folder_button.config(state=tk.DISABLED)
    else:
        messagebox.showinfo("Scan Complete", "No viruses found in the selected folder.")

def delete_file():
    global selected_file
    if selected_file:
        os.remove(selected_file)
        messagebox.showinfo("File Deleted", "The file has been deleted.")
        selected_file = None
        file_label.config(text="Selected File: None")
        delete_button.config(state=tk.DISABLED)
        open_folder_button.config(state=tk.DISABLED)
    else:
        messagebox.showinfo("Error", "No file selected to delete.")

def open_folder():
    global selected_file
    if selected_file:
        folder_path = os.path.dirname(selected_file)
        os.startfile(folder_path)
    else:
        messagebox.showinfo("Error", "No file selected.")
def scheduled_scan():
    global selected_folder
    if selected_folder:
        infected_files = scan_folder(selected_folder)
        if infected_files:
            for file_path in infected_files:
                os.remove(file_path)
            messagebox.showinfo("Scheduled Scan Complete", f"{len(infected_files)} infected files have been deleted.")
        else:
            messagebox.showinfo("Scheduled Scan Complete", "No infected files found.")
    else:
        messagebox.showinfo("Error", "No folder selected for scheduled scan.")

# Function to start the scheduled scan
def start_scheduled_scan():
    schedule.every(1).days.do(scheduled_scan)  # Schedule a daily scan
    while True:
        schedule.run_pending()
        time.sleep(1)

def go_back():
    root_antivirus.destroy()
    create_main_window()

def create_antivirus_window():
    
    global root_antivirus

    # Create the antivirus window
    root_antivirus = tk.Tk()
    root_antivirus.title("Antivirus Software")
    root_antivirus.state('zoomed')
    root_antivirus.configure(bg='white')

    
    heading_label = tk.Label(root_antivirus, text="Antivirus Software", font=("Arial", 16, "bold"), bg='white')
    heading_label.pack(pady=(10, 20))

    
    select_file_button = tk.Button(root_antivirus, text="Select a File", command=select_file, font=("Arial", 12))
    select_file_button.pack(pady=(0, 10))
    global file_label
    file_label = tk.Label(root_antivirus, text="Selected File: None", font=("Arial", 10), bg='white')
    file_label.pack()

    global scan_file_button
    scan_file_button = tk.Button(root_antivirus, text="Scan for Virus (File)", command=scan_file_command, font=("Arial", 12), state=tk.DISABLED)
    scan_file_button.pack(pady=(10, 20))

    # Add button to select a folder
    select_folder_button = tk.Button(root_antivirus, text="Select a Folder", command=select_folder, font=("Arial", 12))
    select_folder_button.pack(pady=(0, 10))
    # Add button to scan a URL
    scan_url_button = tk.Button(root_antivirus, text="Scan a URL", command=scan_url_command, font=("Arial", 12))
    scan_url_button.pack(pady=(10, 20))

    # Add entry box for entering the URL
    global url_entry
    url_entry = tk.Entry(root_antivirus, font=("Arial", 12), width=40)
    url_entry.pack(pady=(0, 10))
    global folder_label
    folder_label = tk.Label(root_antivirus, text="Selected Folder: None", font=("Arial", 10), bg='white')
    folder_label.pack()

    global scan_folder_button
    scan_folder_button = tk.Button(root_antivirus, text="Scan for Virus (Folder)", command=scan_folder_command, font=("Arial", 12), state=tk.DISABLED)
    scan_folder_button.pack(pady=(10, 20))

    global progress_label
    progress_label = tk.Label(root_antivirus, text="", font=("Arial", 12), bg='white')
    progress_label.pack()

    global delete_button
    delete_button = tk.Button(root_antivirus, text="Delete File", command=delete_file, font=("Arial", 12), state=tk.DISABLED)
    delete_button.pack(pady=(10, 20))

    global open_folder_button
    open_folder_button = tk.Button(root_antivirus, text="Open Folder", command=open_folder, font=("Arial", 12), state=tk.DISABLED)
    open_folder_button.pack(pady=(10, 20))

    # Add button to start scheduled scan
    start_scheduled_scan_button = tk.Button(root_antivirus, text="Start Scheduled Scan", command=start_scheduled_scan, font=("Arial", 12))
    start_scheduled_scan_button.pack(pady=(10, 20))

    # Add a back button
    back_button = tk.Button(root_antivirus, text="Back", command=go_back, font=("Arial", 12))
    back_button.pack(pady=(20, 10))

    root_antivirus.mainloop()
  

def create_main_window():
    global root

    # Create the main window
    root = tk.Tk()
    root.title("Operating System Project")
    root.geometry("800x600")
    canvas = tk.Canvas(root, width=800, height=600)
    canvas.pack()

    global label_project
    label_project = tk.Label(canvas, text="OPERATING SYSTEM PROJECT", font=("Arial", 16, "bold"), fg="black")
    label_project.place(relx=0.5, rely=0.15, anchor=tk.CENTER)

    team_members_text = "Daksh Singla\nSahil Agrawal\nSarthak Luhadia"

    global label_team
    label_team = tk.Label(canvas, text=team_members_text, font=("Arial", 12, "bold"), fg="black")
    label_team.place(relx=0.5, rely=0.35, anchor=tk.CENTER)

    next_button_image = Image.open("C:/Users/Acer/Downloads/pngtree-start-button-with-gradient-and-icon-png-image_2257339-removebg-preview.png")
    next_button_image = Image.open("C:/Users/Acer/Downloads/pngtree-start-button-with-gradient-and-icon-png-image_2257339-removebg-preview.png")
    next_button_image = ImageTk.PhotoImage(next_button_image)

    def open_antivirus_window():
        global root_antivirus
        root.destroy()  # Close the initial window
        create_antivirus_window()

    next_button = tk.Button(canvas, image=next_button_image, command=open_antivirus_window, bd=0)
    next_button.image = next_button_image
    next_button.place(relx=0.5, rely=0.7, anchor=tk.CENTER)

    root.mainloop()


if __name__ == "__main__":
    create_main_window()
