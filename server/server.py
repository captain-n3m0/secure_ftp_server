import socket
import ssl
import os
import hashlib

SERVER_CERT = 'server.crt'
SERVER_KEY = 'server.key'
PORT = 2121
STORAGE_DIR = 'server_storage'

os.makedirs(STORAGE_DIR, exist_ok=True)

def sha256_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def even_parity(byte_data):
    return sum(bin(b).count('1') for b in byte_data) % 2 == 0

def handle_client(connstream):
    while True:
        try:
            cmd = connstream.recv(1024).decode()
            if not cmd: break

            if cmd.startswith("UPLOAD"):
                _, filename, filesize = cmd.split()
                filesize = int(filesize)
                filepath = os.path.join(STORAGE_DIR, filename)

                with open(filepath, 'wb') as f:
                    bytes_read = 0
                    while bytes_read < filesize:
                        chunk = connstream.recv(min(4096, filesize - bytes_read))
                        if not chunk: break
                        f.write(chunk)
                        bytes_read += len(chunk)

                client_hash = connstream.recv(1024).decode()
                client_parity = connstream.recv(1024).decode()

                server_hash = sha256_hash(filepath)
                with open(filepath, 'rb') as f:
                    parity = even_parity(f.read())

                if client_hash == server_hash and client_parity == str(parity):
                    connstream.send(b"UPLOAD SUCCESS")
                else:
                    os.remove(filepath)
                    connstream.send(b"INTEGRITY CHECK FAILED")

            elif cmd.startswith("DOWNLOAD"):
                _, filename = cmd.split()
                filepath = os.path.join(STORAGE_DIR, filename)
                if not os.path.exists(filepath):
                    connstream.send(b"FILE NOT FOUND")
                    continue

                filesize = os.path.getsize(filepath)
                connstream.send(f"{filesize}".encode())

                with open(filepath, 'rb') as f:
                    while chunk := f.read(4096):
                        connstream.sendall(chunk)

                connstream.send(sha256_hash(filepath).encode())

                with open(filepath, 'rb') as f:
                    connstream.send(str(even_parity(f.read())).encode())

            elif cmd == "LIST":
                files = os.listdir(STORAGE_DIR)
                connstream.send("\n".join(files).encode())

            elif cmd == "EXIT":
                break

        except Exception as e:
            print("Error:", e)
            break

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('', PORT))
        sock.listen(5)
        print(f"Secure FTP Server running on port {PORT}...")

        while True:
            client, addr = sock.accept()
            print("Connected:", addr)
            with context.wrap_socket(client, server_side=True) as connstream:
                handle_client(connstream)

if __name__ == "__main__":
    start_server()
