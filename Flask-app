from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash

# Ініціалізація додатка Flask
app = Flask(__name__)

# Конфігурація бази даних
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Конфігурація JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Замініть на ваш секретний ключ

# Ініціалізація SQLAlchemy та JWT
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Модель користувача
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Модель книги
class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    published_year = db.Column(db.Integer, nullable=True)

# Ендпоінт для реєстрації
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Ендпоінт для логіну
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Створити JWT токен
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200

# Ендпоінт для логауту
@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "Successfully logged out"})
    unset_jwt_cookies(response)
    return response, 200

# Захищений ендпоінт для отримання списку книг
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    # Отримати ідентифікатор користувача з токена
    current_user = get_jwt_identity()
    
    # Логіка для отримання всіх книг
    books = Book.query.all()
    books_data = [{"id": book.id, "title": book.title, "genre": book.genre, "published_year": book.published_year} for book in books]
    return jsonify(books_data), 200

# Захищений ендпоінт для додавання книги
@app.route('/books', methods=['POST'])
@jwt_required()
def add_book():
    data = request.get_json()
    title = data.get('title')
    genre = data.get('genre')
    published_year = data.get('published_year')

    if not title or not genre:
        return jsonify({"error": "Title and genre are required"}), 400

    new_book = Book(title=title, genre=genre, published_year=published_year)
    db.session.add(new_book)
    db.session.commit()

    return jsonify({"message": "Book added successfully"}), 201

# Захищений ендпоінт для видалення книги
@app.route('/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    return jsonify({"message": "Book deleted successfully"}), 200

# Захищений ендпоінт для оновлення книги
@app.route('/books/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    data = request.get_json()
    book = Book.query.get_or_404(book_id)

    title = data.get('title')
    genre = data.get('genre')
    published_year = data.get('published_year')

    if title:
        book.title = title
    if genre:
        book.genre = genre
    if published_year:
        book.published_year = published_year

    db.session.commit()
    return jsonify({"message": "Book updated successfully"}), 200

# Головний запуск програми
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Створення таблиць, якщо їх ще немає
    app.run(debug=True)
