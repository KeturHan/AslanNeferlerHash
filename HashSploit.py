import time, sys

e	= '\033[0m'
r	= '\033[1;31m'
g	= '\033[1;32m'
y	= '\033[1;33m'
w	= '\033[1;37m'


def havali(parametre, time_sleep = 7):
    soz=[]
    for i in parametre+"\n":
        soz.append(i)
        time.sleep(time_sleep)
        sys.stdout.write(str(soz[0]))
        sys.stdout.flush()
        soz.remove(i) 
    
def bekle():
    say = 0
    karakter = ["\\", "|", "/", "-"]
    
    while True:
        if say == 1: break
        
        for i in range(0, 4):
            sys.stdout.write("Giriş Başarılı....."+karakter[i]+" \r")
            sys.stdout.flush()
            time.sleep(0.4)
        say += 1
    
def bekle2():
    print ("\n")
    say = 0
    mesaj = "Sistem Hazırlanıyor.."
    
    while True:        
        if say == 2: 
            mesaj = "Sistem Açılıyor.."
        if say == 3:
            mesaj = ""
        if say == 3: break
    
        nokta = ""
        
        for i in range(1, 5):
            sys.stdout.write(mesaj+nokta+"    \r")
            sys.stdout.flush()
            nokta += "."
            time.sleep(1)
            
        time.sleep(1)
        say += 1
        
def bekle3(parametre):
    bos = ""
    boy = len(parametre)
    parametre += " "
    
    for i in range(1, boy+1):
        bos += " "    
    
    for i in range(1, boy+1):
        time.sleep(.1)
        sys.stdout.write(">>"+bos[:-i]+parametre[:i]+"<<\r")
        sys.stdout.flush()
    
    bos = ""
    
    for i in range(1, boy+1):
        time.sleep(.1)
        sys.stdout.write(">>"+parametre[i:]+bos+"\r")
        sys.stdout.flush()
        bos += " "
        
def bekle4():
    dolu = u""
    bos  = ""
    
    for i in range(1):
        bos += ">"
    
    say = 1
    
    for i in range(1):
        sys.stdout.write(dolu+bos[:-i]+"|Sisteme Giriş Yapmak Üzeresiniz !!"+str(say)+"\r")
        sys.stdout.flush()
        dolu += u"\x00"
        say  += 2
        time.sleep(.0)

yazi=(g+'''\n[+]Yapacağınız işlemlerden kendiniz sorumlusunuz!\n[+]  İllegal kullanımlarda sorumlu değiliz!\n[+]Bu Toolün bütün hakları AslanNeferlere aittir..\n[+]https://aslanneferler.org\n
[+] Biz İzlemeye Devam Edin...İyi seyirler :)\n
''')
                    
                    
if __name__ == "__main__":
    bekle3(r+"AslanNeferler Tim  Coded By KeturHan")
    havali(yazi, 0.03)
    bekle4()
    bekle2()
    bekle()
    havali(r+"AslanNeferlerTim..GECE UZUN MEVZU DERİN....\t\t\t", 0.1)


from urllib.request import urlopen
import hashlib
import os
import signal
import time 

print(w+"##########################")
print("AslanNeferler Tim        # ")                     
print(r+"===========>>>By         #")
print("KeturHan                 #")                 
print("##########################")

time.sleep(5)

def keyboardInterruptHandler(signal, frame):
    print("\nprogram kapatıldı.".format(signal))
    exit(0)

signal.signal(signal.SIGINT , keyboardInterruptHandler)

os.system('clear')

e	= '\033[0m'
r	= '\033[1;31m'
g	= '\033[1;32m'
y	= '\033[1;33m'
w	= '\033[1;37m'

print(r+"[1] seçim yapın  MD-5")
print(w+"[2] seçim yapın SHA-1")
print(r+"[3] seçim yapın  SHA-256")
print(w+"[4] seçim yapın SHA-512")
print(r+"[5] seçim yapın SHA-224")
print(y+"[6] hash karması oluştur\n")




opt = input(w+"seçimyapın : ")
print('\n')

#örnek sözlükbağlantısı
#https://gist.githubusercontent.com/roycewilliams/4003707694aeb44c654bf27a19249932/raw/7afc95e02df629515960a3e45109e6f88db3a99e/rockyou-top15k.txt

#örnek karmalar :
#kelime--> !QAZ2wsx
#MD5 --> a1e0476879cab2a76cc22c80bbf364dd
#SHA1 --> 3357229dddc9963302283f4d4863a74f310c9e80
#SHA224 --> e2543fb1005b10532cec3f962cc56c5b64b829fa197f6ee46b5d8149
#SHA512 --> 4d2fa38025252a7aa0e1d4b22cb7d5981ccde72cf6eea8f102214baf089eb90d2816bb0adedf779d924a89df24d06794d5497533a5345979244e09fa3659ff21
#SHA256 --> 514cedc5a74404407cb25627410a3e8287d284f3da11ac4fea1725a649b9f987

if opt == '2':
    passurl = input('URL girin: ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    sha1 = input(w+'[*] hash değerini girin : ')
    for password in passlist.split('\n'):
        sha1g = hashlib.sha1(bytes(password, 'utf-8')).hexdigest()
        if sha1g == sha1:
            print(g+"[+] doğru şifre: " + str(password))
            quit()
        else:
            print(r+'[-] : ' + str(password))
    
    print('\n')
    print(y+'[*] malesef doğru şifre bulunamadı .')
    print('\n')

if opt == '1':
    passurl = input('URL girin : ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    md5 = input(w+"[*] hash değerini girin : ")
    for password in passlist.split('\n'):
        md5g = hashlib.md5(bytes(password, 'utf-8')).hexdigest()
        if md5g == md5:
            print(g+"[+] doğru şifre : " + str(password))
            quit()
        else:
            print(r+"[-] : " + str(password))
    
    print('\n')
    print(y+'[*] malesef doğru şifre bulunamadı.')
    print('\n')

if opt == '3':
    passurl = input('URL girin : ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    sha256 = input(w+"[*] hash değerini girin : ")
    for password in passlist.split('\n'):
        sha256g = hashlib.sha256(bytes(password, 'utf-8')).hexdigest()
        if sha256g == sha256:
            print(g+'[+] doğru şifre : ' + str(password))
            quit()
        else:
            print(r+'[-] : ' + str(password))
    print('\n')
    print(y+'[*] malesef doğru şifre bulunamadı .')
    print('\n')

if opt == '4':
    passurl = input('URL girin : ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    sha512 = input(w+"[*] hash değerini girin : ")
    for password in passlist.split('\n'):
        sha512g = hashlib.sha512(bytes(password, 'utf-8')).hexdigest()
        if sha512g == sha512:
            print(g+"[+] doğru şifre : " + str(password))
            quit()
        else:
            print(r+'[-] : ' + str(password))
    
    print('\n')
    print(y+'[*] malesef doğru şifre bulunamadı .')
    print('\n')


if opt == '5':
    passurl = input('URL girin : ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    sha224 = input(w+'[*] hash değerini girin : ')
    for password in passlist.split('\n'):
        sha224g = hashlib.sha224(bytes(password, 'utf-8')).hexdigest()
        if sha224g == sha224:
            print(g+"[+] şifre : " + str(password))
            quit()
        else:
            print(r+"[-] : " + str(password))

    print('\n')
    print(y+'[*] malesef doğru şifre bulunamadı .')
    print('\n')




if opt == '6':
    
    os.system('clear')
    
    hv = input(r + "[*] şifrelemek istediğiniz kelimeyi girin : ")

    print('\n')

    hj1 = hashlib.md5()
    hj1.update(hv.encode())
    print(y + '[+] MD5 --> ' + hj1.hexdigest())

    hj2= hashlib.sha1()
    hj2.update(hv.encode())
    print(y + '[+] SHA1 --> ' + hj2.hexdigest())

    hj3 = hashlib.sha224()
    hj3.update(hv.encode())
    print(y + '[+] SHA224 --> ' + hj3.hexdigest())


    hj4 = hashlib.sha512()
    hj4.update(hv.encode())
    print(y + '[+] SHA512 --> ' + hj4.hexdigest())

    hj5 = hashlib.sha256()
    hj5.update(hv.encode())
    print(y + '[+] SHA256 --> ' + hj5.hexdigest())
    print('\n')
