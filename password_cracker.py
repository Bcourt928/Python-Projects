import hashlib
from urllib.request import urlopen

def readwordlist(url):
    try:
        wordlistfile = urlopen(url).read()
    except Exception as e:
        print("Error while reading the wordlist, error:", e)
    return wordlistfile

def hash(password):
    result = hashlib.sha1(password.encode())
    return result.hexdigest()
def bruteforce(guesspasswordlist, actual_password_hash):
    for guess_password in guesspasswordlist:
        if hash(guess_password) == actual_password_hash:
            print(f"Your password is {guess_password}, please change.")
            exit()

url = 'https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt'
actual_password = 'Password1'
actual_password_hash = hash(actual_password)

wordlist = readwordlist(url).decode('UTF-8')
guesspasswordlist = wordlist.split('\n')

bruteforce(guesspasswordlist, actual_password_hash)

print('Could not bruteforce password')
