import sys
from getpass import getpass
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

args = sys.argv

command = args[1]


def getUsernamesDictionary():
    usersDict = {}
    with open("users.bin", "rb") as file:
        rows = file.read()
        rows = rows.decode()
        rows = rows.strip("\n").split("\n")
        if rows[-1] == '':
            rows.pop()
        for row in rows:
            userdata = row.strip("\n").split(":")
            usersDict[userdata[0]] = [userdata[1], userdata[2], userdata[3]]
    return usersDict


def writeChanges(usersDict):
    with open("users.bin", "wb") as file:
        for key in usersDict.keys():
            row = ""
            row += key + ":"
            for el in usersDict[key]:
                row += str(el) + ":"
            row = row[:-1]
            row += "\n"
            file.write(bytes(row, encoding="utf8"))
        pass


def passwordPrompt():
    while True:
        passwordInput = getpass("Enter password: ")
        repeatedPasswordInput = getpass("Repeat password: ")
        if len(passwordInput) < 8:
            print("Password not long enough")
        if not any(char.isnumeric() for char in passwordInput):
            print("Password must contain a number")
        if not any(char.isupper() for char in passwordInput):
            print("Password must contain a upper case character")
        if len(passwordInput) >= 8 \
                and any(char.isnumeric() for char in passwordInput) \
                and any(char.isupper() for char in passwordInput):
            if passwordInput == repeatedPasswordInput:
                return True, passwordInput, "success"
            else:
                return False, passwordInput, "Password mismatch"


usersDictionary = getUsernamesDictionary()
username = args[2]
user = usersDictionary.get(username, None)

# dodavanje korisnickog imena
if command == "add":
    if user is not None:
        print("User already exists")
        exit(1)
    success, password, message = passwordPrompt()
    if success:
        salt = get_random_bytes(16).hex()
        hashedPassword = scrypt(password, salt, 16, N=2 ** 14, r=8, p=1).hex()
        usersDictionary[username] = [hashedPassword, False, salt]
        print("User successfully added")
    else:
        print("User add failed.", message)
# promjena lozinke
elif command == "passwd":
    if user is not None:
        success, password, message = passwordPrompt()
        if success:
            userData = usersDictionary[username]
            salt = get_random_bytes(16).hex()
            userData[0] = scrypt(password, salt, 16, N=2 ** 14, r=8, p=1).hex()
            userData[1] = str(False)
            userData[2] = salt
            print("Password changed successfully")
        else:
            print("Password change failed. ", message)
    else:
        print("User does not exist")
elif command == "forcepass":
    if user is not None:
        userData = usersDictionary[username]
        userData[1] = str(True)
        print("User will be requested to change password on next login.")
    else:
        print("User does not exist.")
elif command == "del":
    if user is not None:
        usersDictionary.pop(username)
        print("User removed successfully.")
    else:
        print("User does not exist.")
writeChanges(usersDictionary)
