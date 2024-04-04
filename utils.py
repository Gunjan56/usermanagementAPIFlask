from flask_socketio import SocketIO
from flask import Flask, app, request, jsonify
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
import socketio
from models.model import db, User
from flask_mail import Message, Mail
import os
import base64 
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv, dotenv_values
load_dotenv()
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def secure_password(password):
    return generate_password_hash(password)    


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    app.config['UPLOAD_FOLDER'] =  os.getenv('UPLOAD_FOLDER')
    app.config['ALLOWED_EXTENSIONS'] = os.getenv('ALLOWED_EXTENSIONS')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt = JWTManager(app)
    socketio = SocketIO(app)
    return app, socketio
app, socketio = create_app()
mail = Mail(app)

@app.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
   
    data = request.get_json()
    new_password = data['new_password']
    confirm_password = data['confirm_password']
    
    if new_password != confirm_password:
        return jsonify({'message': 'New password and confirm password do not match'}), 400

    email = base64.b64decode(token).decode('utf-8')
    
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        reset_token = base64.b64encode(email.encode('utf-8')).decode('utf-8')

        send_reset_password_email(email, reset_token)

        return jsonify({'message': 'Reset password link sent to your email'})
    else:
        return jsonify({'message': 'User not found'}), 404

def send_reset_password_email(user_email, reset_token):
    msg = Message('Reset Your Password', sender=os.getenv('MAIL_USERNAME'), recipients=[user_email])
    msg.body = f'Reset your password: {reset_token}'
    mail.send(msg)

if __name__ == "__main__":
    socketio.run(app,debug=True, host='localhost', port=5000)
