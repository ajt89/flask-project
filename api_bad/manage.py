import crypto.CryptoWrapper as CryptoWrapper
from flask import Flask, request, make_response, jsonify
from flask_script import Manager, Shell
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

#Constants
from serializer import Serializer as CustomSerializer
#generating the initial rsa key pair
#RSA_PRIVATE, RSA_PUBLIC = CryptoWrapper.generateRSAKeys(1024)
RSA_PRIVATE = '-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQD2C+iKlZIOCPyPmbUsfp3T21wqMe41FSI6WTETRcV8Q2bqaghJ\nvNNJm6+q49YnqFUtmVxU6jquXDnRGdoShidPRtYClL7XTrf35hKCpay1VYFoMKN4\nXRviq7XTojMW9Teu4tDLCC1mV27egsnzdASqnTO+uQI5JWBby8J+5YNwaQIDAQAB\nAoGBAM9t/K8RJ+ADPYGG8VHAsShRr+K2038XARM17IS19qcrX9FScQhRU8OjqDam\n+/3VEXJu74N7MNucTvX1GH8zcGDjP+jm07qyIDN7B2Q4LCtUlznnI9RwPpQhXHFG\nN/pN8pDVpMKgbMI276qS+n+piyeiUUsvEU8kZuiYooDDb5XxAkEA9/nixwBJtIu8\nJxOAtgWD2Gvv26MX6dzRmn8X73BjYwH8eXRvOb11bAwnIUADqUMjaS/1p1tybqJv\nlcHMRgtMxQJBAP4CCeTAOl5WaI38Dz/7BemfkiXMMVZhVDSbDqkv0MtZdWEjbBGb\nG4ZmtTzFvwxnIAKyfEcmq8bOPwVs+ny8V1UCQC2ZGpVDPUpgw4lf8bQG0ZazSljV\n5ajQPQ6uviT+QphLHjTrLySr7PKgTXW0wreWK+XEtuQ+UY18ew5Lo5dhro0CQQDI\nfq90gk8QO8BXoogfBnNKTww7DYw8FKM0ytetr/JtMHW4cQ9Sbk4xrkyMZcJBdf0M\nY/o450tbp1yTWcv2PWvpAkBMRr22K8bcuUmcIet+mjX7w1tmy7XYFQidxsAN1CFI\nAgJXMBzSxwa5pk/6jrUAXJezvNHSZNTQK3WjuTaf0AHF\n-----END RSA PRIVATE KEY-----'
RSA_PUBLIC = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2C+iKlZIOCPyPmbUsfp3T21wq\nMe41FSI6WTETRcV8Q2bqaghJvNNJm6+q49YnqFUtmVxU6jquXDnRGdoShidPRtYC\nlL7XTrf35hKCpay1VYFoMKN4XRviq7XTojMW9Teu4tDLCC1mV27egsnzdASqnTO+\nuQI5JWBby8J+5YNwaQIDAQAB\n-----END PUBLIC KEY-----'

# Application configs
app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost:3306/venbo'
auth = HTTPBasicAuth()

db = SQLAlchemy(app)


class CRUDMixin(object):
    """ Mixin that provides convenience methods for create, read, update, delete """

    @classmethod
    def create(cls, **kwargs):
        """ Create a new record and save it to the database. """
        instance = cls(**kwargs)
        return instance.save()

    def update(self, commit=True, **kwargs):
        """ Update specific fields to a record. """
        # Prevent changing IDS
        kwargs.pop('id', None)
        for attr, value in kwargs.iteritems():
            # Flask-restful makes everything None by default
            if value is not None:
                setattr(self, attr, value)
        return commit and self.save() or self

    def save(self, commit=True):
        """ Save the record """
        db.session.add(self)
        if commit:
            db.session.commit()
        return self

    def delete(self, commit=True):
        """ Remove the record from database. """
        db.session.delete(self)
        return commit and db.session.commit()


# SQLAlchemy ORM Models
class Model(db.Model, CRUDMixin):
    """ A mixin that adds a surrogate integer 'primary key' column named
    ``id`` to any declarative-mapped class.
    """

    __abstract__ = True
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)

    @classmethod
    def get_by_id(cls, id):
        if id <= 0:
            raise ValueError('ID must not be negative or zero!')
        if any(
            (isinstance(id, basestring) and id.isdigit(),
            isinstance(id, (int, float))),
        ):
            return cls.query.get(int(id))
        return None

    @classmethod
    def list_all(cls):
        return cls.query.all()

class User(Model, Serializer):
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(80))
    otp_balance = db.Column(db.Text)
    otp_password = db.Column(db.Text)
    rsa_otpkey = db.Column(db.Text)

    def __init__(self, username, email, password):
        otp_key = CryptoWrapper.otpGenerate()
        self.username = username
        self.email = email
        self.otp_balance = self.otp_encrypt(otp_key, '0.0')
        self.otp_password = self.otp_encrypt(otp_key, password)
        self.rsa_otpkey = self.encrypt_key(otp_key)

    def otp_encrypt(self, otp_key, data):
        cipher = CryptoWrapper.otpEncrypt(otp_key, data)
        return cipher

    def otp_decrypt(self, otp_key, data):
        decrypted = CryptoWrapper.otpDecrypt(otp_key, data)
        return decrypted

    def encrypt_key(self, otp_key):
        cipher = CryptoWrapper.rsaPublicEncrypt(RSA_PUBLIC, otp_key)
        return str(cipher)

    def decrypt_key(self):
        decrypted = CryptoWrapper.rsaPrivateDecrypt(RSA_PRIVATE,eval(self.rsa_otpkey))
        return decrypted

    def update_email(self, email):
        self.email = email
        return True

    def get_balance(self):
        otp_key = self.decrypt_key()
        balance = self.otp_decrypt(otp_key,self.otp_balance)
        return balance

    def update_balance(self, balance):
        otp_key = self.decrypt_key()
        current_balance = self.otp_decrypt(otp_key,self.otp_balance)
        new_balance = float(current_balance) + float(balance)
        self.otp_balance = self.otp_encrypt(otp_key, str(new_balance))
        return True

    def update_password(self, password):
        otp_key = self.decrypt_key()
        self.otp_password = self.otp_encrypt(otp_key, password)
        return True


    def verify_password(self, otp_key, password):
        decrypted = CryptoWrapper.otpDecrypt(otp_key, self.otp_password)
        if decrypted == password:
            return True
        return False

    def verify_otpkey(self, otp_key):
        decrypted = CryptoWrapper.rsaPrivateDecrypt(RSA_PRIVATE, eval(self.rsa_otpkey))
        if decrypted == otp_key:
            return True
        return False

    def __repr__(self):
        return '<User %r>' % self.username

    def as_dict(cls):
        return dict(cls.__dict__.items())

    def serialize(self):
        d = CustomSerializer.serialize(self)
        return d

    def generate_auth_token(self, expiration = 1800):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        return user

    credit_card = db.relationship('CreditCard', foreign_keys='CreditCard.user_id')
    sent_transactions = db.relationship('Transaction', foreign_keys='Transaction.sender_id')
    received_transactions = db.relationship('Transaction', foreign_keys='Transaction.recipient_id')

class CreditCard(Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    otp_card_num = db.Column(db.Text)

    def __init__(self, user_id, card_num):
        self.user_id = user_id
        otp_key = self.get_otp_key()
        self.otp_card_num = self.encrypt_credit_card(card_num)

    def __repr__(self):
        return '<CreditCard %r>' % self.user_id

    def decrypt_credit_card(self):
        otp_key = self.get_otp_key()
        decrypted = CryptoWrapper.otpDecrypt(self.otp_card_num)
        return decrypted

    def encrypt_credit_card(self, card_num):
        otp_key = self.get_otp_key()
        cipher = CryptoWrapper.otpEncrypt(otp_key,card_num)
        return cipher

    def get_otp_key(self):
        user = User.get_by_id(self.user_id)
        rsa_otpkey = user.rsa_otpkey
        otp_key = CryptoWrapper.rsaPrivateDecrypt(RSA_PRIVATE, eval(rsa_otpkey))
        return otp_key

    def update_credit_card(self, user_id, card_num):
        otp_card_num = self.encrypt_credit_card(user_id, card_num)
        self.otp_card_num = otp_card_num
        return True

    def get_credit_card(self, user_id):
        credit_card = self.decrypt_credit_card(user_id)
        return credit_card

class Transaction(Model, Serializer):
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Text)


    def __init__(self, sender_id, recipient_id, amount):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.amount = amount

    def __repr__(self):
        return str(self.serialize())

@app.route('/', methods=['GET'])
def index():
    return 'index'

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.json
        user = db.session.query(User).filter_by(username=data['username']).first()
        otp_key = user.decrypt_key()
        if user is not None and user.verify_password(otp_key,data['password']):
            return jsonify({'message': 'Login success.'}), 201

    return jsonify({'message': 'Login unsuccessful.'}), 403

@app.route('/token', methods=['GET'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({ 'token': token.decode('ascii') })

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username = username_or_token).first()
        otp_key = user.decrypt_key()
        if not user or not user.verify_password(otp_key, password):
            return False
    g.user = user
    return True

@app.route('/list_users', methods=['GET'])
def view_users():
    user = db.session.query(User.username)
    returnVal = [row for row in user.all()]

    return jsonify(returnVal), 200

@app.route('/view_transactions/<user_id>', methods=['GET'])
def view_transactions(user_id):
    trans1 = db.session.query(Transaction).filter_by(sender_id=user_id).all()
    trans2 = db.session.query(Transaction).filter_by(recipient_id=user_id).all()
    json1 = Transaction.serialize_list(trans1)
    json2 = Transaction.serialize_list(trans2)
    json = json1+json2

    return jsonify(json), 200

@app.route('/password/<user_id>', methods=['GET'])
def view_password(user_id=None):
    try:
        u = db.session.query(User).filter_by(id=user_id).first()
        otp_password = u.otp_password
        encrypted_key = u.rsa_otpkey
        otp_key = CryptoWrapper.rsaPrivateDecrypt(RSA_PRIVATE,eval(encrypted_key))
        returnVal = CryptoWrapper.otpDecrypt(otp_key, otp_password)
    except:
        u_p = db.session.query(User.otp_password)
        ups = [row for row in u_p.all()]
        returnVal = ups

    return jsonify(returnVal), 200

@app.route('/balance/<user_id>', methods=['GET'])
def view_balance(user_id=None):
    try:
        u = db.session.query(User).filter_by(id=user_id).first()
        encrypted_balance = u.otp_balance
        encrypted_key = u.rsa_otpkey
        otp_key = CryptoWrapper.rsaPrivateDecrypt(RSA_PRIVATE,eval(encrypted_key))
        returnVal = CryptoWrapper.otpDecrypt(otp_key, encrypted_balance)
    except:
        u_b = db.session.query(User.otp_balance)
        bs = [row for row in u_b.all()]
        returnVal = bs

    
    return jsonify(returnVal), 200

@app.route('/credit_card/<user_id>', methods=['GET'])
def view_credit_card(user_id=None):
    try:
        u = db.session.query(User).filter_by(id=user_id).first()
        cc = db.session.query(CreditCard).filter_by(id=u.id).first()
        encrypt_credit_card = cc.otp_card_num
        encrypted_key = u.rsa_otpkey
        otp_key = CryptoWrapper.rsaPrivateDecrypt(RSA_PRIVATE,eval(encrypted_key))
        returnVal = CryptoWrapper.otpDecrypt(otp_key, encrypt_credit_card)
    except:
        cc_cc = db.session.query(CreditCard.otp_card_num)
        ccs = [row for row in cc_cc.all()]
        returnVal = ccs

    return jsonify(returnVal), 200

@app.route('/makePayment/<sender_id>/to/<recipient_id>', methods=['POST'])
def make_payment(sender_id, recipient_id):

    return

# Initiate and populate the database
with app.app_context():
    # Extensions like Flask-SQLAlchemy now know what the "current" app
    # is while within this block. Therefore, you can now run........
    db.create_all()


manager = Manager(app)


def _make_context():
    """Return context dict for a shell session so you can access
    app, db, and the User model by default.
    """
    return {'User': User, 'CreditCard': CreditCard, 'Transaction': Transaction, 'db': db, 'jsonify':jsonify}


manager.add_command('shell', Shell(make_context=_make_context))

if __name__ == '__main__':
    manager.run()
