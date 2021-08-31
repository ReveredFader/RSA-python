from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import zlib
import msvcrt
import pyperclip
import base64
import os
import time
import sys
import threading


def decrypt_path_blob(path, private_key):
    try:
        fd = open(path, "rb")
        encrypted_blob = fd.read()
        fd.close()

        rsakey = RSA.importKey(private_key)
        rsakey = PKCS1_OAEP.new(rsakey)

        # Base 64 decode the data
        encrypted_blob = base64.b64decode(encrypted_blob)

        chunk_size = 128
        offset = 0
        decrypted = "".encode()

        while offset < len(encrypted_blob):
            # The chunk
            chunk = encrypted_blob[offset: offset + chunk_size]

            decrypted += rsakey.decrypt(chunk)

            offset += chunk_size

        print(path, "\n- decrypted!")
        fd = open(path, "wb")
        fd.write(zlib.decompress(decrypted))
        fd.close()

    except:
        print(path + "\n- error")
        return 0


def encrypt_path_blob(path, public_key):
    try:
        fd = open(path, "rb")
        blob = fd.read()
        fd.close()

        rsa_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)

        # compress the data first
        blob = zlib.compress(blob)

        chunk_size = 86
        offset = 0
        end_loop = False
        encrypted = "".encode()

        while not end_loop:

            chunk = blob[offset:offset + chunk_size]

            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += " ".encode() * (chunk_size - len(chunk))

            encrypted += rsa_key.encrypt(chunk)

            offset += chunk_size

        print(path, "\n- encrypted!")
        fd = open(path, "wb")
        fd.write(base64.b64encode(encrypted))
        fd.close()

    except:
        print("Error")
        return 0


def decrypt_blob(encrypted_blob, private_key):
    try:
        rsakey = RSA.importKey(private_key)
        rsakey = PKCS1_OAEP.new(rsakey)

        # Base 64 decode the data
        encrypted_blob = base64.b64decode(encrypted_blob)

        chunk_size = 128
        offset = 0
        decrypted = "".encode()

        while offset < len(encrypted_blob):
            # The chunk
            chunk = encrypted_blob[offset: offset + chunk_size]

            decrypted += rsakey.decrypt(chunk)

            offset += chunk_size

        return zlib.decompress(decrypted)
    except:
        return 0


def encrypt_blob(blob, public_key):
    try:
        rsa_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)

        # compress the data first
        blob = zlib.compress(blob)

        chunk_size = 86
        offset = 0
        end_loop = False
        encrypted = "".encode()

        while not end_loop:

            chunk = blob[offset:offset + chunk_size]

            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += " ".encode() * (chunk_size - len(chunk))

            encrypted += rsa_key.encrypt(chunk)

            offset += chunk_size

        return base64.b64encode(encrypted)
    except:
        return 0


def keyhunter():
    try:
        key = msvcrt.getch()
        key = key.decode('utf8')
        return key
    except Exception as e:
        raise e


def main():
    os.system('cls')
    print("1) Encrypt file.\n"
          "2) Encrypt text.\n"
          "3) Decrypt file.\n"
          "4) Decrypt text.\n"
          "5) RSA key generator\n"
          "Any other key to exit.\n")

    key = keyhunter()

    if key == '1':
        try:
            path = input("Enter the path to the file or folder"
            " (in folder we can encrypt not much 80 files)\n--> ")
            if not os.path.isfile(path) and not os.path.isdir(path):
                print("Path not accessible!\n")
                time.sleep(1)
                return

            key = input("Enter public RSA key\n")
            if os.path.isfile(path):
                key = base64.b64decode(key)
                os.system('cls')
                print(key.decode())
                time.sleep(1)
                os.system('cls')

                fd = open(path, "rb")
                unencrypted_blob = fd.read()
                fd.close()
                print("Encrypting...")

                encrypted_blob = encrypt_blob(unencrypted_blob, key)

                if encrypted_blob == 0:
                    print("Encrypting Error!")
                    time.sleep(1)
                    return

                os.system('cls')
                name = input("Enter output file name\n--> ")
                if name == '':
                    name = path
                fd = open(name, "wb")
                fd.write(encrypted_blob)
                fd.close()

            elif os.path.isdir(path):
                key = base64.b64decode(key)
                all_file = []
                for root, dirs, files in os.walk(path):
                    for file in files:
                        all_file.append(root + '\\' + file)
                # Запускаем многопоточность
                thread_list = []

                if len(all_file) >= 80:
                    much = 80
                else:
                    much = len(all_file)

                x = 0
                for i in range(much):
                    t = threading.Thread(target=encrypt_path_blob,
                        args=(all_file[x], key))
                    thread_list.append(t)
                    t.start()
                    x += 1

                for t in thread_list:
                    t.join()
                os.system('cls')

                print("Done")
                time.sleep(1)
        except:
            return

    elif key == '2':
        try:
            message = input("Please input your text\n")
            message = message.encode('utf8')

            key = input("Enter public RSA key\n")
            key = base64.b64decode(key)

            encrypted = encrypt_blob(message, key)
            os.system('CLS')

            print('Your message:')
            encrypted = base64.b64encode(encrypted)
            print(encrypted.decode())

            print('Press "1" to copy message\n')
            key = keyhunter()
            if key == "1":
                pyperclip.copy(str(encrypted.decode()))
        except:
            return

    elif key == '3':
        try:

            path = input("Enter the path to the file or folder "
                "(in folder we can decrypt not much 80 files)\n--> ")
            if not os.path.isfile(path) and not os.path.isdir(path):
                print("Path not accessible!\n")
                time.sleep(1)
                return

            key = input("Enter private RSA key\n")
            if os.path.isfile(path):
                key = base64.b64decode(key)
                os.system('cls')
                print(key.decode())
                time.sleep(1)
                os.system('cls')

                fd = open(path, "rb")
                encrypted_blob = fd.read()
                fd.close()

                print("Decrypting...")

                decrypted = decrypt_blob(encrypted_blob, key)

                if key == '0':
                    print("Decrypting Error!\n")
                    time.sleep(1)
                    return

                os.system('cls')
                print("Decrypting done\n")
                fd = open(path, "wb")
                fd.write(decrypted)
                fd.close()
                time.sleep(1)

            elif os.path.isdir(path):  # Доделать
                key = base64.b64decode(key)
                all_file = []
                for root, dirs, files in os.walk(path):
                    for file in files:
                        all_file.append(root + '\\' + file)

                # Запускаем многопоточность и расшифровку
                thread_list = []

                if len(all_file) >= 80:
                    much = 80
                else:
                    much = len(all_file)

                x = 0
                for i in range(much):
                    t = threading.Thread(target=decrypt_path_blob,
                        args=(all_file[x], key))
                    thread_list.append(t)
                    t.start()
                    x += 1

                for t in thread_list:
                    t.join()

                os.system('cls')
                print("Done")
                time.sleep(1)
        except:
            return

    elif key == '4':
        try:
            message = input("Please input text to decode\n")
            message = base64.b64decode(message)

            key = input("Enter private RSA key\n")
            key = base64.b64decode(key)
            # decrypting
            decrypted = decrypt_blob(message, key)

            # show message
            os.system('cls')
            message = decrypted.decode('utf-8')
            print("Your message:\n", message)
            input()
        except:
            return

    elif key == '5':
        try:
            os.system("cls")
            print("Generate a key...\n")
            key = RSA.generate(1024)

            publickey = key.publickey().exportKey('PEM')
            privatekey = key.exportKey('PEM')
            os.system("cls")

            print("Generation is finished\n"
                "press 1 to view key\n"
                "press 2 to copy key's\n"
                "press 3 to export key's\n")
            key = keyhunter()
            os.system('cls')
            if key == '1':
                print((base64.b64encode(publickey)).decode(), '\n',
                    (base64.b64encode(privatekey)).decode())
                input('Press any key...')

            elif key == '2':
                keys = (base64.b64encode(publickey)).decode()
                keys += '\n\n'
                keys += (base64.b64encode(privatekey)).decode()
                pyperclip.copy(keys)

                print('Done\n')
                time.sleep(1)

            elif key == '3':
                name = input("Enter output file name or press"
                " enter to use default name\n--> ")
                if name == '':
                    name = "RSA_Keys.txt"
                keys = (base64.b64encode(publickey)).decode()
                keys += '\n\n'
                keys += (base64.b64encode(privatekey)).decode()
                with open(name, 'w', encoding='utf-8') as f:
                    f.write(keys)
                print("Done\n")
                time.sleep(1)
        except:
            return

    else:
        os.system('cls')
        print("Good luck!\n")
        time.sleep(0.8)
        sys.exit(0)


if __name__ == '__main__':
    while True:
        main()