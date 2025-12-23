import html
from datetime import *
import time
import sqlite3
import hashlib
import hmac
import logging
import secrets





def simple_create_sql():
    conn = sqlite3.connect('all_data.db')
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                salt TEXT,
                hashed_password TEXT
            )
        ''')

        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_name ON users (name)')  #magic!!!


        print('sqlite3 ready')
    except Exception as e:
        print(f"sqlite create error:{e}")


    conn.commit()
    conn.close()
simple_create_sql()

def time_delay(start_time):
    try:
        delay = time.time() - start_time
        if delay < 0.8:
            time.sleep(0.8 - delay)
    except Exception as e:
        pass

def add_user(username:str, password:str)->dict[str,any]:
    conn = None
    try:
        conn = sqlite3.connect('all_data.db')
        cursor = conn.cursor()
        salt = secrets.token_hex(16)
        add_hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

        cursor.execute(
            "INSERT INTO users (name, salt, hashed_password) VALUES (?,?,?)",
            (html.escape(username), salt , add_hashed_password)
        )
        conn.commit()
        return {'success':True, 'message':'User added successfully'}
    except sqlite3.IntegrityError:
        time.sleep(0.5)
        return {'success':False,'message':'Username already exist'}
    except Exception as e:
        logging.error(f'(add_user)register error:{e}')
        return {'success':False,'message':'error'}
    finally:
        if conn:
            conn.close()

def verify_the_password(username:str,password:str) -> dict[str, any]:
    try:
        start_time = time.time()

        with sqlite3.connect('all_data.db') as conn:
            the_cursor = conn.cursor()
            cursor = the_cursor.execute('SELECT salt, hashed_password FROM users WHERE name = ?',
                                  (html.escape(username),))
            user_item = cursor.fetchone()
            if user_item is None:
                time_delay(start_time)
                return {'success': False, 'message': 'username or password is wrong'}
            salt = user_item[0]
            stored_hashed_password = user_item[1]

            input_hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

            password_correct = hmac.compare_digest(input_hashed_password, stored_hashed_password)

            if password_correct:
                #no delay in success because……he success! its no matter that has there any delay if he success= he know pass and username
                #if username is wrong we wont verify the pass so we don't need more delay in there
                return {'success': True, 'message': f'user:{html.escape(username)}Login success!'}
            time_delay(start_time)
            return{'success':False, 'message':'username or password is wrong'}

    except sqlite3.OperationalError as e:
        logging.error(f'(verify_password)Database error during login: {e}')
        return {'success':False,'message':'System error, please try again later'}

    except TypeError as e:
        logging.error(f'(verify_password)Data format error: {e}')
        return {'success':False,'message':'System error'}

    except Exception as e:
        logging.error(f'(verify_password)Unexpected login error: {e}')
        return {'success':False,'message':'Login failed, please try again'}