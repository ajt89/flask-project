import sqlalchemy

DATABASE = 'venbo'
url = 'mysql+pymysql://root@localhost:3306'

engine = sqlalchemy.create_engine(url)  # connect to server

destroy_str = "DROP DATABASE IF EXISTS %s ;" % (DATABASE)
create_str = "CREATE DATABASE IF NOT EXISTS %s ;" % (DATABASE)
engine.execute(destroy_str)
engine.execute(create_str)
engine.execute("USE venbo;")

from manage import app

with app.app_context():
    from manage import db,User,CreditCard,Transaction 
    db.create_all()
    allan = User.create(username='ajt89',email='ajt89@drexel.edu',password='password1')
    kento = User.create(username='kn737',email='kn737@drexel.edu',password='password2')
    amanda = User.create(username='ac3298',email='ac3298@drexel.edu',password='password3')

    allan.update_balance(200)
    kento.update_balance(250)
    amanda.update_balance(275)
    
    credit1 = CreditCard.create(user_id=allan.id, card_num='123456789')
    credit2 = CreditCard.create(user_id=kento.id, card_num='987654321')
    credit3 = CreditCard.create(user_id=amanda.id, card_num='000000000')

    '''
    balance1 = Balance.create(user_id=allan.id, amount='200')
    balance2 = Balance.create(user_id=kento.id, amount='250')
    balance3 = Balance.create(user_id=amanda.id, amount='275')
    '''

    transaction1 = Transaction.create(sender_id=allan.id,recipient_id=kento.id,amount='25')
    transaction2 = Transaction.create(sender_id=kento.id,recipient_id=amanda.id,amount='15')
    transaction3 = Transaction.create(sender_id=amanda.id,recipient_id=allan.id,amount='30')

