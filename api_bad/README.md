# Backend Flask API


## Local Setup
1. Install virtual env
```
pip install virtualenv
```

2. Create virtualenv
```
virtualenv env
```

3. Activate virtual env
```
source env/bin/activate
```

4. Install dependencies
```
pip install -r requirements.txt
```

5. Run MySQL container
```
docker run --name=venbo_mysql -p 3306:3306 -e MYSQL_ALLOW_EMPTY_PASSWORD=true mysql:5.7.17
```

6. Load the database schema
```
python setup.py
```

7. Run the API in terminal
```
python manage.py runserver -p <port>
```
