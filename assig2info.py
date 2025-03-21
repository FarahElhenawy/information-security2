from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import pymysql

# Step 1: Create database if not exists
connection = pymysql.connect(
    host='localhost',
    user='root',
    password=''  # Add your MySQL root password if any
)

try:
    with connection.cursor() as cursor:
        cursor.execute("CREATE DATABASE IF NOT EXISTS farah_db")
finally:
    connection.close()

# Step 2: Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'farah'
app.config['JWT_SECRET_KEY'] = 'farah'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/farah_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Step 3: Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Step 4: Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# Step 5: Create tables
with app.app_context():
    db.create_all()

# Step 6: Routes

# User Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 409

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(name=data['name'], username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))  # FIXED
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

# Update User
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user = get_jwt_identity()
    if str(current_user) != str(id):  # Compare as strings
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    user = User.query.get_or_404(id)
    user.name = data.get('name', user.name)
    user.username = data.get('username', user.username)
    if 'password' in data:
        user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

# Add Product
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.get_json()
    new_product = Product(
        pname=data['pname'],
        description=data.get('description', ''),
        price=data['price'],
        stock=data['stock']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully'})

# Get All Products
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([{
        'pid': p.pid,
        'pname': p.pname,
        'description': p.description,
        'price': p.price,
        'stock': p.stock,
        'created_at': str(p.created_at)
    } for p in products])

# Get Product by ID
@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    p = Product.query.get_or_404(pid)
    return jsonify({
        'pid': p.pid,
        'pname': p.pname,
        'description': p.description,
        'price': p.price,
        'stock': p.stock,
        'created_at': str(p.created_at)
    })

# Update Product
@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.get_json()
    p = Product.query.get_or_404(pid)
    p.pname = data.get('pname', p.pname)
    p.description = data.get('description', p.description)
    p.price = data.get('price', p.price)
    p.stock = data.get('stock', p.stock)
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

# Delete Product
@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    p = Product.query.get_or_404(pid)
    db.session.delete(p)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

# Start the server
if __name__ == '__main__':
    app.run(debug=True)
