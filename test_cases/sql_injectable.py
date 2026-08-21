import sqlite3


username = input("Username: ")

connection = sqlite3.connect("users.db")

query = "SELECT * FROM users WHERE username = '" + username + "'"

connection.execute(query)