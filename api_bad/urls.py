from flask import request, jsonify, make_response

from manage import app, db, User, Transaction


@app.route('/')
def index():
    username = request.cookies.get('username')
    if username:
        user = db.session.query(User).filter_by(username=username).first()
        return 'User is logged in: {}'.format(user.username), 200
    return 'User needs to login.', 200


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.data
        user = db.session.query(User).filter_by(username=data['username']).first()

        if user is not None and user.verify_password(data['password']):
            resp = make_response()
            resp.set_cookie('username', user.username)
            return resp, 201

    return 'User login unsuccessful.', 204


@app.route('/editProfile', methods=['POST'])
def edit_profile():
    return 'editProfile'


@app.route('/makePayment/', methods=['POST'])
def make_payment():
    return 'makePayment'


@app.route('/requestPayment', methods=['POST'])
def request_payment():
    return 'requestPayment'


@app.route('/viewTransactions/<user_id>', methods=['GET'])
def view_transactions(user_id):
    trans1 = db.session.query(Transaction).filter_by(sender_id=user_id).all()
    trans2 = db.session.query(Transaction).filter_by(recipient_id=user_id).all()

    transactions = trans1.union(trans2)

    return jsonify(transactions), 200


@app.route('/viewBalance/<user_id>', methods=['GET'])
def view_balance(user_id):
    balance = db.session.query(Balance).filter_by(user_id=user_id).first()
    return jsonify(balance), 200


@app.route('/pullFromBank', methods=['POST'])
def pull_from_bank():
    return 'pullFromBank'


@app.route('/pushToBank', methods='POST')
def push_to_bank():
    return 'pushToBank'
