# Antivirus Software

This project is a simple antivirus software that can scan files, folders, and URLs for potential viruses and malicious content using the VirusTotal API. The software is built using Python and Tkinter for the graphical user interface.

## Features

- **File Scan**: Scan individual files for viruses.
- **Folder Scan**: Scan all files within a selected folder for viruses.
- **URL Scan**: Check the safety of a URL.
- **Encryption**: Encrypt and isolate infected files.
- **Scheduled Scan**: Schedule daily scans for a selected folder.
- **File and Folder Management**: Delete infected files and open their containing folders.

## Prerequisites

- Python 3.x
- Tkinter
- Pillow
- requests
- cryptography
- schedule

You can install the required packages using:

```bash
pip install pillow requests cryptography schedule
```

## Usage

1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/antivirus-software.git
cd antivirus-software
```

2. **Run the Application**

```bash
python antivirus_software.py
```

3. **Main Window**

   - The main window displays the project name and team members.
   - Click the "Start" button to open the antivirus window.

4. **Antivirus Window**

   - **Select a File**: Click the "Select a File" button to choose a file and then click "Scan for Virus (File)" to scan it.
   - **Select a Folder**: Click the "Select a Folder" button to choose a folder and then click "Scan for Virus (Folder)" to scan all files within the folder.
   - **Scan a URL**: Enter a URL in the text box and click "Scan a URL" to check its safety.
   - **Scheduled Scan**: Click the "Start Scheduled Scan" button to initiate daily scans for the selected folder.
   - **Delete File**: If a virus is found in a file, you can choose to delete it.
   - **Encrypt File**: If a virus is found, you can choose to encrypt and isolate the file.

## Project Structure

- `antivirus_software.py`: Main application file containing all functionality.
- `README.md`: Documentation file.
- `requirements.txt`: List of required packages.

## API Key

The VirusTotal API key is hardcoded in the script. Replace `"your_api_key"` with your own API key.

## Note

- The software uses the VirusTotal API for scanning files, folders, and URLs. Ensure you have a valid API key.
- The encryption feature uses the `cryptography` library to encrypt infected files.

## Acknowledgements

- [VirusTotal API](https://www.virustotal.com/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html)
- [Pillow](https://python-pillow.org/)
- [cryptography](https://cryptography.io/)
- [schedule](https://github.com/dbader/schedule)
```

Replace `"your_api_key"` with your actual VirusTotal API key in the appropriate sections of your code and update the project structure and acknowledgments as necessary. This `README.md` provides a comprehensive guide for users to understand and use your antivirus software.
