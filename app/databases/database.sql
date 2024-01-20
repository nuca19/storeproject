CREATE TABLE IF NOT EXISTS users (
    UsersId INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    ProductsId INT NOT NULL,
    productName TEXT NOT NULL UNIQUE,
    price DECIMAL(10, 2) NOT NULL,
    quantity INT NOT NULL
);

CREATE TABLE IF NOT EXISTS encomendas (
    EncomendaId INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    totalPrice INTEGER NOT NULL,
    products TEXT NOT NULL,
    userAddress TEXT NOT NULL,
    city TEXT NOT NULL,
    cardName TEXT NOT NULL,
    cardNumber TEXT NOT NULL,
    cardExp TEXT NOT NULL,
    cardCCV TEXT NOT NULL    
);

CREATE TABLE IF NOT EXISTS comentarios (
    comentarioID INTEGER PRIMARY KEY AUTOINCREMENT,
    productID INTEGER NOT NULL, 
    username TEXT NOT NULL,
    comentario TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);