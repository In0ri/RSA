import base64
import hashlib
import random
import math
from ast import literal_eval
from Crypto.Util import number


def euclide(b, m):
    a1, a2, a3 = 1, 0, m
    b1, b2, b3 = 0, 1, b
    q = 0

    while ((b3 > 1)):
        # print(q,a1,a2,a3,b1,b2,b3)
        q = a3 // b3
        t = b3
        b3 = a3 % b3
        o1, o2 = a1, a2
        a1, a2, a3 = b1, b2, t
        b1 = o1 - q * b1
        b2 = o2 - q * b2
        if b3 == 0:
            gdc = a3
        elif b3 == 1:
            gdc = b2
    return (gdc)


def encrypt(m_raw, e, n):
    c_list = []
    crypt = ''
    for x in m_raw:
        c_list.append(pow(ord(x), e, n))
    # encode
    crypt = bytes(str(c_list), 'utf-8')
    encoded_bytes = base64.b64encode(crypt)
    mysign = encoded_bytes.decode('utf-8')
    return mysign


def decrypt(c, d, n):
    m_list = []
    messages = ''
    encoded_bytes = c.encode('utf-8')
    decoded_bytes = base64.b64decode(encoded_bytes)
    mysign_raw = decoded_bytes.decode('utf-8')
    mysign = literal_eval(mysign_raw)

    for m in mysign:
        m_list.append(pow(int(m), d, n))
    for r in m_list:
        messages += '' + chr(r)
    return messages


# def isPrime(a, b):
#     while b != 0:
#         a, b = b, a % b
#     return a == 1


# def listPrime(phi):
#     coprimes = []
#     for i in range(1, phi + 1):
#         if isPrime(i, phi):
#             coprimes.append(i)
#     return coprimes

def is_prime(n, k=5):
    if n <= 3:
        return n == 2 or n == 3

    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True



def hash_file(path):
    file = path
    file_hash = hashlib.sha256()
    with open(file, 'rb') as f:
        fb = f.read()
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read()
    return file_hash.hexdigest()


def menu():
    print("\nNhap \"1\" de tao cap khoa")
    print("Nhap \"2\" de ki file")
    print("Nhap \"3\" de xac minh chu ki")
    print("Nhap \"0\" de quay lai menu")
    print("Nhap exit de thoat")


emoji_map_status = {
    "resolved": "✅",
    "firing": "⛔",
}


def main():
    menu()
    option = input("\nMoi ban nhap: ")
    while option.upper() != "EXIT":
        if option == '1':
            p = number.getPrime(2048)
            q = number.getPrime(2048)
            # p, q = 79, 53
            # e = 71
            n = p * q
            phi = (p - 1) * (q - 1)
            # e = random.choice(listPrime(phi))

            while True:
                e = random.randrange(65537, 2**864)
                if e % 2 == 1 and is_prime(e):
                    break

            print("e = ", e)
            d = euclide(e, phi)
            if d < 0:
                d = phi + d

            print(f"Cap so tu nhien p={p}, q={q}")
            print(f"Khoa cong khai n={n}, e={e}")
            print(f"Khoa bi mat d={d}")
            exit
        elif option == '2':
            print("================================================")
            print("===================Tao chu ki===================")
            path_sign = input("Nhap duong dan file: ")
            # Hash file
            hash_raw = hash_file(path_sign)
            print("Hash file: ", hash_raw)
            m_raw = list(hash_raw)

            # Result
            c = encrypt(m_raw, d, n)
            print("signature: ", c)
            print("---------------------------------")

        elif option == '3':
            print("=====================================================")
            print("===================Kiem tra chu ki===================")
            path_check = input("Nhap duong dan file: ")
            print("Nhap chu ki: ")
            m = decrypt(c, e, n)
            if m == hash_file(path_check):
                print(
                    "{} Chu ki hop le. File khong bi thay doi".format(
                        emoji_map_status["resolved"]))
            else:
                print(
                    "{} Chu ki khong hop le. File da bi thay doi".format(
                        emoji_map_status["firing"]))
        else:
            print("------------------------------------------------")
            print("-----Tham so khong hop le. Moi ban nhap lai-----")
            print("------------------------------------------------")

        option = input("\nMoi ban nhap: ")


if __name__ == "__main__":
    main()
