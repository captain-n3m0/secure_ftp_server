import socket
import ssl
import hashlib
from tkinter import *
from tkinter import filedialog, messagebox

SERVER_ADDR = 'localhost'
PORT = 2121

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

        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = self.context.wrap_socket(raw_sock, server_hostname=SERVER_ADDR)
        self.conn.connect((SERVER_ADDR, PORT))

        self.create_widgets()
        self.list_files()

    def create_widgets(self):
        self.listbox = Listbox(self.root, width=60)
        self.listbox.pack(pady=10)

        Button(self.root, text="Refresh", command=self.list_files).pack(pady=2)
        Button(self.root, text="Upload File", command=self.upload_file).pack(pady=2)
        Button(self.root, text="Download Selected", command=self.download_file).pack(pady=2)

    def list_files(self):
        self.conn.send(b"LIST")
        data = self.conn.recv(4096).decode()
        self.listbox.delete(0, END)
        for f in data.splitlines():
            self.listbox.insert(END, f)

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        filename = file_path.split("/")[-1]
        filesize = os.path.getsize(file_path)
        file_hash = sha256_hash(file_path)

        with open(file_path, 'rb') as f:
            parity = even_parity(f.read())

        self.conn.send(f"UPLOAD {filename} {filesize}".encode())
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                self.conn.sendall(chunk)

        self.conn.send(file_hash.encode())
        self.conn.send(str(parity).encode())

        status = self.conn.recv(1024).decode()
        messagebox.showinfo("Upload Status", status)
        self.list_files()

    def download_file(self):
        filename = self.listbox.get(ACTIVE)
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
        self.conn.send(b"EXIT")
        self.conn.close()
        self.root.destroy()

if __name__ == "__main__":
    import os
    root = Tk()
    client = SecureFTPClient(root)
    root.protocol("WM_DELETE_WINDOW", client.on_close)
    root.mainloop()
