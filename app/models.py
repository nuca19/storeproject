import sqlite3
from datetime import date
from flask import Flask
from flask_bcrypt import Bcrypt

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create tables
    with open('databases/database.sql', 'r') as f:
        sql = f.read()
        c.executescript(sql)

    conn.commit()
    conn.close()


def clear_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # List of all tables
    tables = ['users', 'products', 'encomendas', 'comentarios']

    # Delete all rows from all tables
    for table in tables:
        c.execute(f"DELETE FROM {table}")

    conn.commit()
    conn.close()

def add_user():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    pw = Bcrypt().generate_password_hash('123').decode('utf-8') 
    c.execute("INSERT OR IGNORE INTO users (username,email,password) VALUES (?,?,?)",('admin','ad@gmail.com',pw))

    conn.commit()
    conn.close()


def add_products():
    db = sqlite3.connect('database.db')
    cursor = db.cursor()

    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1000, 'TeeUA', 20, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1001, 'HoodieUA', 35, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1002, 'DetiTee', 20, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1003, 'DetiCrewNeck', 30, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1004, 'DetiWaterBottle', 15, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1005, 'DetiHat', 10, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1006, 'DiaryUA', 12, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1007, 'PhoneCaseUA', 15, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1008, 'DetiSlides', 20, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1009, 'DetiBlanket', 12, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1010, 'LaptopSleeveUA', 10, 100);")
    cursor.execute("INSERT OR IGNORE INTO products (ProductsId, productName, price, quantity) VALUES (1011, 'DetiStuffedBunny', 15, 100);")

    db.commit()
    db.close()