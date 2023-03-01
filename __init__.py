import base64
import hashlib
import random
from numpy import sqrt 
from Crypto.Util import number


def euclide(b, m):
    a1,a2,a3 = 1, 0, m
    b1, b2, b3 = 0, 1, b
    q=0
    
    while( (b3 > 1)):
        # print(q,a1,a2,a3,b1,b2,b3)
        q = a3//b3
        t = b3
        b3 = a3%b3
        o1,o2 = a1, a2
        a1, a2, a3 = b1, b2, t
        b1 = o1 - q*b1
        b2 = o2 - q*b2
        if b3 == 0:
            gdc = a3
        elif b3 == 1:
            gdc = b2
    return (gdc)

def encrypt(m_raw, e, n):
    c_list = []
    crypt=''
    for x in m_raw:
        c_list.append(pow(ord(x), e, n))
    for r in c_list:
        crypt += '' + chr(r)
    #encode
    encodedBytes = base64.b64encode(crypt.encode("utf-8"))
    mysign = str(encodedBytes, "utf-8")
    return mysign

def decrypt (c, d, n):
    m_list = []
    messages = ''
    decodedBytes = base64.b64decode(c.encode("utf-8"))
    mysign_raw = str(decodedBytes,"utf-8")
    mysign = list(mysign_raw)
    for m in mysign:
        m_list.append(pow(ord(m), d, n))
    for r in m_list:
        messages += '' + chr(r)
    return messages

def isPrime(n):
    if n < 2:
        return False
    elif n == 2:
        return True
    else:
        for i in range(2, int(sqrt(n)) + 1):
            if n % i == 0:
                return False
    return True

def listPrime(phi):
    list = []
    for i in range(1, phi + 1):
        if isPrime(i): list.append(i)
    return list

def hash_file (path):
    file = path # Location of the file (can be set a different way)
    #BLOCK_SIZE = 65536 # The size of each read from the file
    file_hash = hashlib.sha256() # Create the hash object, can use something other than `.sha256()` if you wish
    with open(file, 'rb') as f: # Open the file to read it's bytes
        fb = f.read() # Read from the file. Take in the amount declared above
        while len(fb) > 0: # While there is still data being read from the file
            file_hash.update(fb) # Update the hash
            fb = f.read() # Read the next block from the file
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
            p = number.getPrime(10)
            q = number.getPrime(10)
            # p, q = 79, 53 
            # e = 71
            n = p*q
            phi = (p-1)*(q-1)
            e = random.choice(listPrime(phi))

            print("e = ",e)
            d = euclide(e, phi)
            if d < 0 : d = phi + d

            print(f"Cap so tu nhien p={p}, q={q}")
            print(f"Khoa cong khai n={n}, e={e}")
            print(f"Khoa bi mat d={d}")
            exit
        elif option == '2':
            print("================================================")
            print("===================Tao chu ki===================")
            path_sign = input("Nhap duong dan file: ")
            #Hash file
            hash_raw = hash_file(path_sign)
            print("Hash file: ",hash_raw)
            m_raw = list(hash_raw)
            
            #Result
            c = encrypt(m_raw, e, n)
            print("signature: ",c)
            print("---------------------------------")
            print("Nhap duong dan file: ")
        elif option == '3':
            print("================================================")
            print("===================Tao chu ki===================")
            path_check = input("Nhap duong dan file: ")
            print("Nhap chu ki: ")
            m = decrypt(c, d, n)
            if m == hash_file(path_check):
                print("{} Chu ki hop le. File khong bi thay doi".format(emoji_map_status["resolved"]))
            else:
                print("{} Chu ki khong hop le. File da bi thay doi".format(emoji_map_status["firing"]))
        else:
            print("------------------------------------------------")
            print("-----Tham so khong hop le. Moi ban nhap lai-----")
            print("------------------------------------------------")

        # menu()
        option = input("\nMoi ban nhap: ")
        

if __name__ == "__main__":
    main()