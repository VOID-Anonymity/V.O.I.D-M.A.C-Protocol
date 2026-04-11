import base64
import re
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad

# Морзянка только для HEX-символов (0-9, A-F) - это работает БЕЗОШИБОЧНО
HEX_MORSE = {
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    ' ': '/'
}
DECODE_HEX_MORSE = {v: k for k, v in HEX_MORSE.items()}

def validate_key(key_name):
    while True:
        key = input(f"\n[?] Ключ {key_name} (EN, 8-32 симв.): ")
        if not re.fullmatch(r'[a-zA-Z0-9\s.,!?@#$%-]+', key):
            print("[!] Ошибка: Только английские буквы/цифры!")
            continue
        if len(key) < 8:
            print("[!] Ошибка: Минимум 8 символов!")
            continue
        return key[:32]

def text_to_mach_morse(text):
    # Переводим текст в HEX, чтобы морзянка понимала всё
    hex_str = text.encode('utf-8').hex().upper()
    return ' '.join(HEX_MORSE[c] for c in hex_str)

def mach_morse_to_text(morse):
    try:
        hex_str = ''.join(DECODE_HEX_MORSE[word] for word in morse.split())
        return bytes.fromhex(hex_str).decode('utf-8')
    except:
        return None

SALT = b'void_protocol_salt_2026'

def encrypt_mach(data, key_aes, key_chacha):
    # Слой М: HEX-Морзе
    morse_data = text_to_mach_morse(data).encode('utf-8')
    
    # Слой А: AES
    aes_key = scrypt(key_aes, SALT, 32, N=2**14, r=8, p=1)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ct_aes = cipher_aes.encrypt(pad(morse_data, AES.block_size))
    
    # Слой Ч: ChaCha20
    chacha_key = scrypt(key_chacha, SALT, 32, N=2**14, r=8, p=1)
    cipher_chacha = ChaCha20.new(key=chacha_key)
    ct_final = cipher_chacha.encrypt(ct_aes)
    
    return base64.b64encode(cipher_aes.iv + cipher_chacha.nonce + ct_final).decode('utf-8')

def decrypt_mach(encoded_data, key_aes, key_chacha):
    try:
        raw_data = base64.b64decode(encoded_data)
        iv, nonce, ciphertext = raw_data[:16], raw_data[16:24], raw_data[24:]
        
        chacha_key = scrypt(key_chacha, SALT, 32, N=2**14, r=8, p=1)
        cipher_chacha = ChaCha20.new(key=chacha_key, nonce=nonce)
        ct_aes = cipher_chacha.decrypt(ciphertext)
        
        aes_key = scrypt(key_aes, SALT, 32, N=2**14, r=8, p=1)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        morse_bytes = unpad(cipher_aes.decrypt(ct_aes), AES.block_size)
        
        return mach_morse_to_text(morse_bytes.decode('utf-8'))
    except:
        return None

def main():
    print("🌑 V.O.I.D - M.A.Ch Protocol v3 (Ultimate Edition)")
    choice = input("\n1. Зашифровать\n2. Расшифровать\nВыбор > ")
    
    if choice == '1':
        msg = input("Текст: ")
        ka, kc = validate_key("AES"), validate_key("ChaCha20")
        print(f"\nРезультат: {encrypt_mach(msg, ka, kc)}")
    elif choice == '2':
        code = input("Код: ")
        ka, kc = validate_key("AES"), validate_key("ChaCha20")
        res = decrypt_mach(code, ka, kc)
        print(f"\nРасшифровано: {res}" if res else "\n[!] Ошибка ключей!")

if __name__ == "__main__":
    main()
