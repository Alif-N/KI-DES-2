import socket
import threading
from DES import DES

# Konfigurasi Jaringan Server
HOST = '127.0.0.1'
PORT = 8000

# Kunci harus 8 karakter dan sama dengan di client!
SHARED_KEY = "keamanan"

# Inisialisasi DES Engine
des_engine = DES()

# Menangani komunikasi bolak-balik dengan satu client.
def handle_client(conn, addr):
    print(f"\n[KONEKSI] Terhubung dengan {addr}")
    
    # Kirim pesan awal
    welcome_msg = f"Berhasil Terhubung ke Server DES di {HOST}:{PORT}"
    try:
        conn.send(welcome_msg.encode('utf-8'))
    except ValueError as e:
        print(f"[ERROR KRIPTO] {e}. Tutup koneksi.")
        conn.close()
        return

    while True:
        try:
            # 1. Terima data terenkripsi
            ciphertext_hex = conn.recv(1024).decode('utf-8')
            
            if not ciphertext_hex or ciphertext_hex.lower() == 'keluar':
                break
                
            if len(ciphertext_hex) != 16:
                print(f"[WARN] Data diterima tidak 16 karakter heks: {ciphertext_hex}. Diabaikan.")
                continue
            
            # 2. Dekripsi data
            plaintext = des_engine.decrypt(ciphertext_hex, SHARED_KEY)
            print("-" * 40)
            print(f"Ciphertext: {ciphertext_hex}")
            print(f"[{addr[1]} (DEKRIPSI)]: '{plaintext}'")
            print("-" * 40)
            
            # 3. Server membalas (enkripsi)
            response_text = input("Server Kirim (Plaintext 8 Karakter): ")
            
            if len(response_text) != 8:
                print("[WARN] Pesan harus 8 karakter. Kirim 'TUNGGU 8' sebagai gantinya.")
                response_text = "TUNGGU 8"

            if response_text.lower() == 'keluar  ':
                conn.send("keluar".encode('utf-8')) # Kirim sinyal keluar (non-enkripsi)
                break
            
            # 4. Enkripsi dan Kirim balasan
            ciphertext_response = des_engine.encrypt(response_text, SHARED_KEY)
            conn.send(ciphertext_response.encode('utf-8'))

        except ValueError as e:
            print(f"[ERROR KRIPTO] Masalah dengan data/kunci DES: {e}")
        except Exception as e:
            print(f"[ERROR] Koneksi {addr} terputus: {e}")
            break

    conn.close()
    print(f"[KONEKSI] {addr} terputus.")

# Memulai server TCP.
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[SERVER] Server berjalan di {HOST}:{PORT}")
    print(f"[SERVER] Kunci Bersama: {SHARED_KEY}")
    
    while True:
        try:
            conn, addr = server_socket.accept()
            # Menjalankan penanganan client di thread terpisah
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            print(f"[AKTIF] {threading.active_count() - 1} koneksi aktif.")
        except KeyboardInterrupt:
            server_socket.close()
            print("\n[SERVER] Server dimatikan.")
            break

if __name__ == "__main__":
    start_server()