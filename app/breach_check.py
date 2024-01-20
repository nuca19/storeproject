import hashlib
import requests


def sha1Hash(toHash):
    try:
        messageDigest = hashlib.sha1()
        stringM = str(toHash)
        byteM = bytes(stringM, encoding='utf')
        messageDigest.update(byteM)
        return messageDigest.hexdigest()
    except TypeError:
        raise "String to hash was not compatible"

def breach_check(password):
    pwhash = sha1Hash(password).upper()
    first_5_chars = pwhash[:5]

    url = f"https://api.pwnedpasswords.com/range/{first_5_chars}" #pwned api to check if password has been breached
    r = requests.get(url)

    result = 0
    for line in r.text.splitlines():
        rhash, count = line.split(":")
        if rhash == pwhash[5:]:
            result = int(count)
            break

    return result #times password was found in breached database
