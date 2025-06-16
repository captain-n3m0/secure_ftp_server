import socket
import ssl
import hashlib
import os
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog

def sha256_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def even_parity(byte_data):
    return sum(bin(b).count('1') for b in byte_data) % 2 == 0

class SecureFTPClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure FTP Client")

        self.conn = None
        self.setup_connection()

    def setup_connection(self):
        self.connect_window = Toplevel(self.root)
        self.connect_window.title("Connect to Server")

        Label(self.connect_window, text="Server IP:").grid(row=0, column=0, padx=10, pady=5)
        Label(self.connect_window, text="Port:").grid(row=1, column=0, padx=10, pady=5)

        self.ip_entry = Entry(self.connect_window)
        self.port_entry = Entry(self.connect_window)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)
        self.port_entry.grid(row=1, column=1, padx=10, pady=5)

        self.ip_entry.insert(0, "127.0.0.1")
        self.port_entry.insert(0, "2121")

        Button(self.connect_window, text="Connect", command=self.connect_to_server).grid(row=2, column=0, columnspan=2, pady=10)

    def connect_to_server(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn = context.wrap_socket(raw_sock, server_hostname=ip)
            self.conn.connect((ip, port))

            self.connect_window.destroy()
            self.create_main_gui()
            self.list_files()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to {ip}:{port}\n\n{e}")

    def create_main_gui(self):
        self.listbox = Listbox(self.root, width=60)
        self.listbox.pack(pady=10)

        Button(self.root, text="Refresh", command=self.list_files).pack(pady=2)
        Button(self.root, text="Upload File", command=self.upload_file).pack(pady=2)
        Button(self.root, text="Download Selected", command=self.download_file).pack(pady=2)

    def list_files(self):
        try:
            self.conn.send(b"LIST")
            data = self.conn.recv(4096).decode()
            self.listbox.delete(0, END)
            for f in data.splitlines():
                self.listbox.insert(END, f)
        except:
            messagebox.showerror("Error", "Unable to retrieve file list.")

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        file_hash = sha256_hash(file_path)

        with open(file_path, 'rb') as f:
            parity = even_parity(f.read())

        try:
            self.conn.send(f"UPLOAD {filename} {filesize}".encode())
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    self.conn.sendall(chunk)

            self.conn.send(file_hash.encode())
            self.conn.send(str(parity).encode())

            status = self.conn.recv(1024).decode()
            messagebox.showinfo("Upload Status", status)
            self.list_files()
        except Exception as e:
            messagebox.showerror("Upload Failed", str(e))

    def download_file(self):
        filename = self.listbox.get(ACTIVE)
        if not filename:
            messagebox.showwarning("No File Selected", "Please select a file to download.")
            return

        self.conn.send(f"DOWNLOAD {filename}".encode())

        reply = self.conn.recv(1024).decode()
        if reply == "FILE NOT FOUND":
            messagebox.showerror("Error", "File not found on server.")
            return

        filesize = int(reply)
        data = b''
        while len(data) < filesize:
            data += self.conn.recv(min(4096, filesize - len(data)))

        received_hash = self.conn.recv(1024).decode()
        received_parity = self.conn.recv(1024).decode()

        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if not save_path:
            return

        with open(save_path, 'wb') as f:
            f.write(data)

        local_hash = sha256_hash(save_path)
        with open(save_path, 'rb') as f:
            parity = even_parity(f.read())

        if received_hash == local_hash and received_parity == str(parity):
            messagebox.showinfo("Download", "File downloaded and verified.")
        else:
            messagebox.showerror("Download", "File corrupted during transfer!")

    def on_close(self):
        try:
            if self.conn:
                self.conn.send(b"EXIT")
                self.conn.close()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    root = Tk()
    app = SecureFTPClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
