from flask import Flask, render_template,url_for,session,redirect,request,flash,abort, jsonify, make_response
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect 
import sqlite3
import requests

from models import *
from breach_check import *
from datetime import timedelta
import secrets
import re
import os
import pathlib


app = Flask(__name__)

app.secret_key = secrets.token_urlsafe(16)  #session token 128 bits CWE 331 

#COOKIES
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_PATH'] = "/"
app.config['SESSION_COOKIE_HTTPONLY'] = True

csrf = CSRFProtect(app) #csrf protection

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev


#database
with app.app_context():
    init_db()
    #clear_db()
    add_products()
    add_user()


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper



#routes
@app.route('/')
def index():
    if 'user' in session:
        session.clear()
    return render_template('index.html')


@app.route('/home')
@login_is_required
def home():
    return render_template('home.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        session.clear()        
        return redirect('/login')

    if(request.method == 'POST'):
        username = request.form.get('username')
        password = request.form.get('password')  

        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT UsersId,password FROM users WHERE username = ?",(username,)) 

        validLogin = cursor.fetchone()
        cursor.close()
        db.close()

        if(validLogin == None):
            return render_template('login.html', message="Invalid username")

        if  validLogin[0] and Bcrypt().check_password_hash(validLogin[1],password):    

            session['user'] = username          #guarda o username na sessão
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=20)   #tempo da sessão ativa

            db = sqlite3.connect("database.db")
            cursor = db.cursor()
            cursor.execute("SELECT email FROM users WHERE username = ?",(username,)) 

            email = cursor.fetchone()
            cursor.close()
            db.close()
            
            return redirect('/home')
        else:
            return render_template('login.html', message="Incorrect password")

    return render_template('login.html')



@app.route('/newPassword', methods=['GET', 'POST'])
def newPassword():

    if 'user' in session:
        return redirect('/home')

    if(request.method == 'POST'):
        user = request.form.get('user')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        new_password = re.sub(' +', ' ', new_password)

        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT UsersId,password FROM users WHERE username = ? AND email = ?",(user,email))
        validation = cursor.fetchone()
        cursor.close()
        db.close()

        if validation == None:
             return render_template('changePassword.html', message="Invalid username or email")

        if validation[0]:
            if Bcrypt().check_password_hash(validation[1],current_password):
                if len(new_password)<12:
                    return render_template('changePassword.html',message="Password must have 12 or more characters ") #after checking for spaces
                
                br = breach_check(new_password)
                print(br)
                if br > 0: #if password has been found in a breach database    
                    return render_template('changePassword.html',message="Password has been found in a breach database. Please choose another one")
            
                new_hashed_password = Bcrypt().generate_password_hash(new_password).decode('utf-8')   
                db = sqlite3.connect("database.db")
                cursor = db.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE username = ? ",(new_hashed_password,user))
                db.commit()
                cursor.close()
                db.close()
                return redirect('/login')
            else:
                return render_template('changePassword.html', message="Incorrect current password")
        
    return render_template('changePassword.html')



@app.route('/register', methods=['GET', 'POST'])    #validar inputs
def register():
    if 'user' in session:
        return redirect('/userPage')

    if(request.method == 'POST'):
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        password = re.sub(' +', ' ', password) #consecutive multiple spaces may be replaced by a single space

        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT UsersId FROM users WHERE username = ? OR email = ?",(username,email))
        validRegist = cursor.fetchone()
        cursor.close()
        db.close()

        if validRegist:
            return render_template('registerPage.html', message="Username or email already being used")

        br = breach_check(password)
        print(br)
        if br > 0: #if password has been found in a breach database
            return render_template('registerPage.html',message="Password has been found in a breach database. Please choose another one")        
        
        else:
            if len(password)<12:
                return render_template('registerPage.html',message="Password must have 12 or more characters ") #after checking for spaces
                
            hashed_password = Bcrypt().generate_password_hash(password).decode('utf-8')   #hashed password
            db = sqlite3.connect("database.db")
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",(username,email,hashed_password))
            db.commit()
            cursor.close()
            db.close()
            return redirect('/login')

    return render_template('registerPage.html')




@app.route('/export_data', methods=['GET'])
def export_user_data():
    username = getUserName()
    if username == None:
        return redirect('/login')
    else:
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT EncomendaId,totalPrice,products,userAddress,city FROM encomendas WHERE username = ?",(username,))
        result = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(result)
    



@app.route('/delete_data', methods=['POST'])
def delete_user_data():
    if 'user' not in session:
        return redirect('/')
    
    username = getUserName()
    if username == None:
        return redirect('/login')
    else:
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("DELETE FROM encomendas WHERE username = ?",(username,))
        cursor.execute("DELETE FROM comentarios WHERE username = ?",(username,))
        db.commit()
        cursor.close()
        db.close()
        return redirect(request.referrer)




@app.route('/delete_account', methods=['POST'])
def delete_user_account():
    if 'user' not in session:
        return redirect('/')
    
    username = getUserName()
    if username == None:
        return redirect('/login')
    elif 'user' in session:
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?",(username,))
        cursor.execute("DELETE FROM encomendas WHERE username = ?",(username,))
        cursor.execute("DELETE FROM comentarios WHERE username = ?",(username,))
        db.commit()
        cursor.close()
        db.close()
        return redirect('/')
    else:
        flash("Accounts logged in with Google services cannot be deleted")
        return redirect('/userPage/')
    


@app.route('/uatshirt')
def uatshirt():
    if 'user' not in session:
        return redirect('/')
    
    uaShirtId = 1000
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1000')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()

    return render_template('uatshirt.html',uaShirtId=uaShirtId,comments=comments) 



@app.route('/uahoodie')
def uahoodie():
    if 'user' not in session:
        return redirect('/')
    uaHoodieId = 1001
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1001')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('uahoodie.html',uaHoodieId=uaHoodieId,comments=comments)


#items routes
@app.route('/detitshirt')
def detitshirt():
    if 'user' not in session:
        return redirect('/')
    detiShirtId = 1002
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1002')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('detitshirt.html',detiShirtId=detiShirtId,comments=comments)

@app.route('/deticrewneck')
def deticrewneck():
    if 'user' not in session:
        return redirect('/')
    detiCrewneckId = 1003
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario, timestamp FROM comentarios Where productID = 1003')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('deticrewneck.html',detiCrewneckId=detiCrewneckId,comments=comments)

@app.route('/detibottle')
def detibottle():
    if 'user' not in session:
        return redirect('/')
    detiBottleId = 1004
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario, timestamp FROM comentarios Where productID = 1004')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()    
    return render_template('detibottle.html',detiBottleId=detiBottleId,comments=comments) 

@app.route('/detihat')
def detihat():
    if 'user' not in session:
        return redirect('/')
    detiHatId = 1005
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()    
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1005')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()    
    return render_template('detihat.html',detiHatId=detiHatId,comments=comments)

@app.route('/uadiary')
def uadiary():

    if 'user' not in session:
        return redirect('/')
    uaDiaryId = 1006
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1006')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()    
    return render_template('uadiary.html',uaDiaryId=uaDiaryId,comments=comments)

@app.route('/uaphonecase')
def uaphonecase():
    if 'user' not in session:
        return redirect('/')
    uaPhonecaseId = 1007
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId,username,comentario,timestamp FROM comentarios Where productID = 1007')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()    
    return render_template('uaphonecase.html',uaPhonecaseId=uaPhonecaseId,comments=comments)

@app.route('/detislides')
def detislides():
    if 'user' not in session:
        return redirect('/')
    detiSlidesId = 1008
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1008')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('detislides.html',detiSlidesId=detiSlidesId,comments=comments) 

@app.route('/detiblanket')
def detiblanket():
    if 'user' not in session:
        return redirect('/')
    detiBlanketId = 1009
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1009')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('detiblanket.html',detiBlanketId=detiBlanketId,comments=comments)

@app.route('/ualaptopsleeve')
def ualaptopsleeve():
    if 'user' not in session:
        return redirect('/')
    uaLaptopsleeveId = 1010
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1010')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('ualaptopsleeve.html',uaLaptopsleeveId=uaLaptopsleeveId,comments=comments)

@app.route('/detipeluche')
def detipeluche():
    if 'user' not in session:
        return redirect('/')
    detiPelucheId = 1011
    db_comentarios = sqlite3.connect('database.db')
    cursor = db_comentarios.cursor()
    cursor.execute('SELECT productId, username,comentario,timestamp FROM comentarios Where productID = 1011')
    comments = cursor.fetchall()
    cursor.close()
    db_comentarios.close()
    return render_template('detipeluche.html',detiPelucheId=detiPelucheId,comments=comments)



@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user' not in session:
        return redirect('/')
    if 'carrinho' not in session:
        return redirect('/')
    if(session['carrinho']['total'] == 0):
        return render_template('home.html')
    
    return render_template('checkOut.html',carrinho=session['carrinho'])
    


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')



@app.route('/userPage/')
def userPage():
    username = getUserName()
    if username == None:
        return redirect('/login')
    else:
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT EncomendaId,totalPrice,products,userAddress FROM encomendas WHERE username = ?",(username,))
        result = cursor.fetchall()
        cursor.close()
        db.close()
        return render_template('userPage.html',username=username,result=result)     #depois temos que ir buscar os dados do utilizador à base de dados como o historico de compras



@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if 'user' not in session:
        return redirect('/')
    
    if 'carrinho' not in session:
        session['carrinho'] = {}
        session['carrinho']['total'] = 0

    if(request.method == 'POST'):
        product_id = request.form.get('product_id')
        # vai procurar o produto na base de dados pelo product_id e adiciona-lo ao carrinho da sessão
        # se o produto já existir no carrinho, aumenta a quantidade
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT productName,price,quantity FROM products WHERE ProductsId = ?",(product_id,))
        result = cursor.fetchone()
        cursor.close()
        db.close()

        if result[2] <= 0:   #out of stock
            flash('Out of stock')
            return render_template('cart.html',carrinho=session['carrinho'])

        name,price,quantity= result
        session['carrinho']['total'] += price
        if product_id not in session['carrinho']:
            session['carrinho'][product_id] = {
                'name': name,
                'price': price,
                'quantity': 0
            }
        
        session['carrinho'][product_id]['quantity'] += 1
        return redirect(request.referrer)
    
    return render_template('cart.html',carrinho=session['carrinho'])



@app.route('/removecart', methods=['GET', 'POST'])
def removecart():

    if 'user' not in session:
        return redirect('/')
    
    if 'carrinho' not in session:
        return redirect('/')

    session['carrinho'] = {}
    session['carrinho']['total'] = 0
    return render_template('cart.html',carrinho=session['carrinho'])



@app.route('/payment', methods=['POST'])
def payment():

    if 'user' not in session:
        return redirect('/')
    
    username = getUserName()
    totalPrice = session['carrinho']['total']
    products = ""
    for p in session['carrinho']:
        if p != 'total':
            products+=session['carrinho'][p]['name']+ " "+ str(session['carrinho'][p]['quantity']) + "|"

    for p in session['carrinho']:
            if p != 'total':
                db = sqlite3.connect("database.db")
                cursor = db.cursor()
                cursor.execute("SELECT quantity FROM products WHERE ProductsId = ?",(p,))
                result = cursor.fetchone()
                cursor.close()
                db.close()
                stock = result[0]
                stock-=session['carrinho'][p]['quantity']
                if stock<0:#check if stock is enough
                    session['carrinho']['total'] -= session['carrinho'][p]['price']*session['carrinho'][p]['quantity']
                    session['carrinho'].pop(p)
                    return redirect('/cart')
                db = sqlite3.connect("database.db")
                cursor = db.cursor()
                cursor.execute("UPDATE products SET quantity = ? WHERE ProductsId = ?",(stock,p))
                db.commit()
                cursor.close()
                db.close()
    
    if(request.method == 'POST'):
        userAddress = request.form.get('userAddress')
        city = request.form.get('city') 
        cardNumber = request.form.get('cardNumber')
        cardName = request.form.get('cardName')
        cardExp = request.form.get('cardExp')
        cardCCV = request.form.get('cardCCV')
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("INSERT INTO encomendas (username,totalPrice,products,userAddress,city,cardName,CardNumber,cardExp,cardCCV) VALUES (?,?,?,?,?,?,?,?,?)",(username,totalPrice,products,userAddress,city,cardName,cardNumber,cardExp,cardCCV))
        db.commit()
        cursor.close()
        db.close()
        #clean carrinho
        session['carrinho'] = {}
        session['carrinho']['total'] = 0

        return redirect('/userPage')
    return redirect('/checkout')



@app.route('/reorder', methods=['GET', 'POST'])
def reorder():
    if 'user' not in session:
        return redirect('/')
    
    username = getUserName()
    
    if(request.method == 'POST'):
        encid = request.form.get('encid')
        db = sqlite3.connect("database.db")
        cursor = db.cursor()
        cursor.execute("SELECT * FROM encomendas WHERE EncomendaId = ? AND username = ?",(encid,username,))
        result = cursor.fetchone()
        cursor.close()
        db.close()
        if result == None:
            return redirect('/userPage')
        else:
            db2 = sqlite3.connect("database.db")
            cursor2 = db2.cursor()
            username = result[1]
            totalPrice = result[2]
            products = result[3]
            userAddress = result[4]
            city = result[5]
            cardName = result[6]
            cardNumber = result[7]
            cardExp = result[8]
            cardCCV = result[9]
            cursor2.execute("INSERT INTO encomendas (username,totalPrice,products,userAddress,city,cardName,CardNumber,cardExp,cardCCV) VALUES (?,?,?,?,?,?,?,?,?)",(username,totalPrice,products,userAddress,city,cardName,cardNumber,cardExp,cardCCV))
            db2.commit()
            cursor2.close()
            db2.close()
            return redirect('/userPage')
    return redirect('/userPage')



@app.route('/search', methods=['GET', 'POST'])
def search(): 
    var=1
    if 'user' not in session:
        var=0

    if(request.method == 'GET'):
        search = request.args.get('search')
        if search == "":
            if var==0:
                return render_template("searchNoAcc.html",search=search)
            else:
                return render_template("search.html",search=search)
        else:
            db = sqlite3.connect("database.db")
            cursor = db.cursor()
            cursor.execute("SELECT productName FROM products WHERE productName LIKE ?", ('%' + search + '%',))
            result = cursor.fetchall()
            cursor.close()
            db.close()

            if var==0:
                return render_template("searchNoAcc.html",search=search,result=result)
            else:
                return render_template("search.html",search=search,result=result)
            
    return render_template("search.html")



@app.route('/newComment', methods=['POST'])
def newComment():
    username = getUserName()
    product_id = request.form.get('product_id')
    comentario= request.form.get('comment')
    db = sqlite3.connect("database.db")
    cursor = db.cursor()
    cursor.execute("INSERT INTO comentarios (productID,username,comentario) VALUES (?,?,?)",(product_id,username,comentario,))
    db.commit()
    cursor.close()
    db.close()
    return redirect(request.referrer)



def getUserName():
    if 'user' in session:
        return session['user']
    return None

def getQuantity():
    return 0
