#!/usr/bin/python3

from werkzeug.security import generate_password_hash
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import getpass


def main():
    # Connect to the DB
    collection = MongoClient()["blog"]["users"]

    # Ask for data to store
    user = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    pass_hash = generate_password_hash(password, method='pbkdf2:sha256')

    # Insert the user in the DB
    try:
        collection.insert({"userlogin": user, "password": pass_hash})
        print ("User created.")
    except DuplicateKeyError:
        print ("User already present in DB.")


if __name__ == '__main__':
    main()
