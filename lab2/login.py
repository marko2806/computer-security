import sys
from getpass import getpass
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

args = sys.argv


def getUsernamesDictionary():
    usersDict = {}
    with open("users.bin", "rb") as file:
        rows = file.read()
        rows = rows.decode()
        rows = rows.strip("\n").split("\n")
        if rows[-1] == '':
            rows.pop()

        for row in rows:
            userData = row.strip("\n").split(":")

            usersDict[userData[0]] = [userData[1], userData[2], userData[3]]
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


usersDictionary = getUsernamesDictionary()
username = args[1]
user = usersDictionary.get(username, None)


password = getpass("Enter password: ")

if user is not None:
    userHash = user[0]
    salt = user[2]
    attemptedHash = scrypt(password, salt, 16, N=2 ** 14, r=8, p=1).hex()

    if attemptedHash == userHash and user[1] == "True":
        newPassword = getpass("New password: ")
        repeatedNewPassword = getpass("Repeated new password: ")
        newPasswordHashOldSalt = scrypt(newPassword, salt, 16, N=2 ** 14, r=8, p=1).hex()
        if newPassword == repeatedNewPassword and newPasswordHashOldSalt != userHash:
            salt = get_random_bytes(16).hex()
            newPasswordHashNewSalt = scrypt(newPassword, salt, 16, N=2 ** 14, r=8, p=1).hex()
            user[0] = newPasswordHashNewSalt
            user[1] = str(False)
            user[2] = salt
            print("Login successful")
        elif newPassword != repeatedNewPassword:
            print("Password mismatch")
        elif newPassword == password:
            print("New password must not be the same as old password")
    elif attemptedHash == userHash and user[1] == "False":
        print("Login successful")
    else:
        print("Username or password is incorrect")
else:
    print("Username or password is incorrect")
writeChanges(usersDictionary)
