import socket
from DES import DES

# --- Konfigurasi Jaringan Client ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8000

# Kunci harus 8 karakter dan sama dengan di server!
SHARED_KEY = "keamanan" 

# Inisialisasi DES Engine
des_engine = DES()

# Memulai client TCP.
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"[CLIENT] Mencoba terhubung ke {SERVER_HOST}:{SERVER_PORT}...")
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print("[CLIENT] Berhasil terhubung.")
        print(f"[CLIENT] Kunci Bersama: {SHARED_KEY}")

        # Terima pesan awal dari server
        initial_text = client_socket.recv(1024).decode('utf-8').strip()
        
        if initial_text:
            print(f"\n[SERVER (DEKRIPSI)]: '{initial_text}'")
            print("-" * 40)

        while True:
            # 1. Client mengirim data (ter-enkripsi)
            message = input("Client Kirim (Plaintext 8 Karakter): ")
            
            if len(message) != 8:
                print("[WARN] Pesan harus 8 karakter. Kirim 'TIDAK 8!' sebagai gantinya.")
                message = "TIDAK 8!"
            
            if message.lower() == 'keluar  ':
                client_socket.send("keluar".encode('utf-8')) # Kirim sinyal keluar (non-enkripsi)
                break
            
            # 2. Enkripsi dan Kirim data
            ciphertext_hex = des_engine.encrypt(message, SHARED_KEY)
            print("-" * 40)
            print(f"[CLIENT ENKRIPSI]: Mengirim {ciphertext_hex}...")
            client_socket.send(ciphertext_hex.encode('utf-8'))

            # 3. Terima data balasan terenkripsi (ciphertext heksadesimal)
            ciphertext_response_hex = client_socket.recv(1024).decode('utf-8').strip()
            
            if not ciphertext_response_hex or ciphertext_response_hex.lower() == 'keluar':
                print("[INFO] Server atau Client memutuskan koneksi.")
                break
            
            if len(ciphertext_response_hex) != 16:
                print(f"[WARN] Data diterima tidak 16 karakter heks: {ciphertext_response_hex}. Diabaikan.")
                continue

            # 4. Dekripsi data balasan
            plaintext_response = des_engine.decrypt(ciphertext_response_hex, SHARED_KEY)
            print("-" * 40)
            print(f"Ciphertext: {ciphertext_response_hex}")
            print(f"[SERVER (DEKRIPSI)]: '{plaintext_response}'")
            print("-" * 40)

    except ConnectionRefusedError:
        print(f"[ERROR] Koneksi ditolak. Pastikan Server berjalan di {SERVER_HOST}:{SERVER_PORT}")
    except ValueError as e:
        print(f"[ERROR KRIPTO] Masalah dengan data/kunci DES: {e}")
    except Exception as e:
        print(f"[ERROR] Terjadi kesalahan: {e}")
    finally:
        client_socket.close()
        print("[CLIENT] Koneksi ditutup.")

if __name__ == "__main__":
    start_client()