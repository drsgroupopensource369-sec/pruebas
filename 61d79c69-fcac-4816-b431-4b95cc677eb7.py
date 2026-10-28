import os
import json
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"

def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una llave segura de 256 bits a partir de la contraseña maestra y la sal."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_vault(password: str):
    """Carga y descifra la bóveda usando la contraseña maestra."""
    try:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        with open(VAULT_FILE, "rb") as f:
            encrypted_data = f.read()
        
        key = derive_key(password, salt)
        f_cipher = Fernet(key)
        decrypted_data = f_cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except Exception:
        print("\n[-] Error: Contraseña incorrecta o archivo de bóveda corrupto.")
        return None

def save_vault(data: dict, password: str, salt: bytes):
    """Cifra y guarda la bóveda en disco."""
    key = derive_key(password, salt)
    f_cipher = Fernet(key)
    json_data = json.dumps(data).encode()
    encrypted_data = f_cipher.encrypt(json_data)
    
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)

def main():
    print("=== [ VaultBox ] ===")
    
    # Comprobar si ya existe la bóveda
    if not os.path.exists(VAULT_FILE) or not os.path.exists(SALT_FILE):
        print("\n[!] No se encontró ninguna bóveda previa.")
        master_password = getpass("Crea tu nueva Contraseña Maestra: ")
        confirm_password = getpass("Confirma tu Contraseña Maestra: ")
        
        if master_password != confirm_password:
            print("[-] Error de contraseña. Saliendo...")
            return
        
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
            
        vault_data = {}
        save_vault(vault_data, master_password, salt)
        print("[+] ¡Bóveda creada exitosamente!\n")
    else:
        master_password = getpass("Ingresa tu Contraseña: ")
        salt = open(SALT_FILE, "rb").read()
        vault_data = load_vault(master_password)
        if vault_data is None:
            return
        print("[+] ¡Bóveda desbloqueada con éxito!\n")

    # Menú principal
    while True:
        print("1. Ver cuentas guardadas")
        print("2. Agregar nueva credencial")
        print("3. Eliminar una credencial")
        print("4. Borrar la bóveda")
        print("5. Salir")
        opcion = input("\nElige una opción (1-5): ").strip()

        if opcion == "1":
            if not vault_data:
                print("\n[i] No se ha encontrado contenido en la Bóveda.\n")
            else:
                print("\n--- Tus Credenciales ---")
                for sitio, creds in vault_data.items():
                    print(f"Sitio/App: {sitio}")
                    print(f"  Usuario/Correo: {creds['usuario']}")
                    print(f"  Contraseña: {creds['password']}")
                    print("-" * 25)
                print()
        elif opcion == "2":
            sitio = input("Nombre del sitio o servicio (ej. GitHub): ").strip()
            usuario = input("Correo o nombre de usuario: ").strip()
            password = getpass("Contraseña a guardar: ").strip()
            
            vault_data[sitio] = {
                "usuario": usuario,
                "password": password
            }
            save_vault(vault_data, master_password, salt)
            print("[+] ¡Credencial guardada y cifrada correctamente!\n")
        elif opcion == "3":
            if not vault_data:
                print("\n[i] La bóveda está vacía, no hay nada que eliminar.\n")
            else:
                print("\n--- Cuentas Disponibles ---")
                for sitio in vault_data.keys():
                    print(f"- {sitio}")
                
                sitio_a_borrar = input("\nEscribe el nombre exacto de la cuenta que quieres eliminar: ").strip()
                if sitio_a_borrar in vault_data:
                    del vault_data[sitio_a_borrar]
                    save_vault(vault_data, master_password, salt)
                    print(f"[+] ¡La cuenta '{sitio_a_borrar}' fue eliminada y la bóveda se actualizó!\n")
                else:
                    print(f"[-] No se encontró ninguna cuenta con el nombre '{sitio_a_borrar}'.\n")
        elif opcion == "4":
            confirmacion = input("\n[!] ¿Estás seguro de borrar TODA la bóveda? Se perderán todas las cuentas guardadas (s/n): ").strip().lower()
            if confirmacion == 's':
                try:
                    if os.path.exists(VAULT_FILE):
                        os.remove(VAULT_FILE)
                    if os.path.exists(SALT_FILE):
                        os.remove(SALT_FILE)
                    print("[+] Bóveda eliminada por completo. El programa se cerrará.")
                    break
                except Exception as e:
                    print(f"[-] Error al eliminar los archivos: {e}\n")
            else:
                print("[i] Operación cancelada.\n")
        elif opcion == "5":
            print("\n¡Saliendo de VaultBox. Adiós!")
            break
        else:
            print("[-] Opción inválida. Intenta de nuevo.\n")

if __name__ == "__main__":
    main()
