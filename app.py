from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow import Schema, fields, post_load
from pprint import pprint
from sqlalchemy import or_
import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

import os

#Init app
app  = Flask(__name__)
baseDir = os.path.abspath(os.path.dirname(__file__))

#database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(baseDir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisIsSecretKey'

#init db
db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    sender = db.Column(db.String(100))
    receiver = db.Column(db.String(100))
    message = db.Column(db.Text)
    subject = db.Column(db.Text)
    wasRead = db.Column(db.Boolean)
    creationDate = db.Column(db.DateTime)


#message Schema
class MessageSchema(ma.Schema):
    class Meta:
        fields = ('id', 'sender', 'receiver', 'message', 'subject', 'creationDate', 'wasRead')

#user Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('public_id', 'name', 'password', 'admin')


messageSchema = MessageSchema()
messagesSchema = MessageSchema(many=True)
userSchema = UserSchema()
usersSchema = UserSchema(many=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# users 
@app.route('/user', methods=['Post'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return  jsonify({"message": "new user was created"})

@app.route('/user', methods=['Get'])
def get_all_users():
    users = User.query.all()
    result = usersSchema.dump(users)
    return jsonify({"users": result})


#authentication
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or auth.username or auth.password:
        make_response('could not verify!', 401, {'WWW-Authonticate' : 'Basic realm = "Login required!"'})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        make_response('could not verify!', 401, {'WWW-Authonticate' : 'Basic realm = "Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('could not verify!', 401, {'WWW-Authonticate' : 'Basic realm = "Login required!"'})

     
#messages
@app.route('/message', methods=['Post'])
@token_required
def add_message(current_user):

    try:
        data = request.get_json()
        sender = current_user.name
        receiver = data['receiver']
        message = data['message']
        subject = data['subject']
        
        new_message = Message(user_id = current_user.id, sender=sender, receiver=receiver, message=message, subject=subject, creationDate=datetime.datetime.utcnow(), wasRead=False)
        db.session.add(new_message)
        db.session.commit()   
    except:
        return jsonify({'message': 'Ooops, something got wrong! Please provide valid message.'})
    return messageSchema.jsonify(new_message)
    

@app.route('/messages' , methods=['Get'])
@token_required
def get_all_messages(current_user):
    userName = current_user.name
    allMessages = Message.query.filter((Message.sender==userName) | (Message.receiver==userName) )
    result = messagesSchema.dump(allMessages)
    if not result:
        result = {"message": "There is no massages for you!"}
    return jsonify(result)

@app.route('/unreadMessages' , methods=['Get'])
@token_required
def get_unread_messages(current_user):
    userName = current_user.name
    allUnreadMessages = Message.query.filter((Message.receiver==userName) & (Message.wasRead.is_(False)))
    result = messagesSchema.dump(allUnreadMessages)
    if not result:
        result = {"message": "There is no unread messages for you!"}
    return jsonify(result)

@app.route('/readMessage/<message_id>' , methods=['Put'])
@token_required
def read_message(current_user, message_id):
    userName = current_user.name
    unreadMessage = Message.query.filter((Message.receiver==userName) & (Message.id==message_id)).first()
    if not unreadMessage:
        result = {"message": "You dont have recieved massages with this id!"}
        return jsonify(result)
    result = messageSchema.dump(unreadMessage)
    unreadMessage.wasRead = True
    db.session.flush()
    db.session.commit()
    return jsonify(result)

@app.route('/deleteMessage/<message_id>', methods=['Delete'])
@token_required
def delete_message(current_user, message_id):
    userName = current_user.name
    messageToDelete = Message.query.filter(((Message.receiver==userName) | (Message.sender==userName)) & (Message.id==message_id)).first()
    if not messageToDelete:
        result = {"message": "You can only delete messages that you sent or recieved!"}
        return jsonify(result)
    result = messageSchema.dump(messageToDelete)
    db.session.delete(messageToDelete)
    db.session.commit()
    result = f"message {message_id} was deleted!"
    return jsonify(result)

#Run server
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)