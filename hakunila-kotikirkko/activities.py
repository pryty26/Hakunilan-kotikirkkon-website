import html
import sqlite3
from datetime import datetime, timedelta
import logging

def commonplace_text(word):
    #make user input better! exemple:
    #for example userinput = sql Attack_tools or Sql_attackTOOls ---> sqlattacktools

    if word and isinstance(word, str):
        text = word.lower().strip()

        for char in [' ','_', '-', ';']:
            text = text.replace(char, '')
        return text
    else:
        return ''
# 1. Init DB (run once)
def init_db():
    try:
        with sqlite3.connect('activities.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    fi_time TEXT,
                    time_iso TEXT,
                    author TEXT,
                    introduction TEXT,
                    filename TEXT
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_name_time_iso ON activities (name, time_iso)')
            conn.commit()
        print('successfully created the database')
    except Exception as e:
        print(e)


# 2. Add activity
def add_activity(name, fi_time, time_iso, author, introduction, filename):
    try:
        if len(name) > 100:
            return{'success':False,'message':f'name must be less than 100 characters'}
        with sqlite3.connect('activities.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                           INSERT INTO activities (name, fi_time, time_iso, author,introduction, filename)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ''', (name, fi_time, time_iso, author, introduction,filename))
            conn.commit()
            return{'success':True,'message':f'{name} is added to the database'}
    except Exception as e:
        print(e)
        logging.error(f"add_activity error:{e}\n")


# 3. Get all activities sorted by time
def get_activities():
    try:
        with sqlite3.connect('activities.db') as conn:
            cursor = conn.cursor()

            cursor.execute('''
                           SELECT name, fi_time, time_iso, author, introduction, filename
                           FROM activities
                           ORDER BY time_iso DESC
                           ''')
            now = datetime.now()
            activities = []
            for row in cursor.fetchall():
                activity = {
                    'name': html.escape(row[0]),
                    'time': row[1],
                    'time_iso': row[2],
                    'author': html.escape(row[3]),
                    'introduction': html.escape(row[4]),
                    'filename': html.escape(row[5])
                }

                try:
                    activity_time = datetime.fromisoformat(row[2])
                    activity_end = activity_time + timedelta(hours=3)

                    if now < activity_time:
                        activity['state'] = "not_started"
                    elif activity_time <= now <= activity_end:
                        activity['state'] = "running"
                    else:
                        activity['state'] = "finished"

                except (ValueError, TypeError):
                    activity['state'] = "unknown"
                activities.append(activity)

            return {'success':True,'message':activities}
    except Exception as e:
        print(e)
        logging.error(f"get_activity error:\n",e)
        return {'success':'error','message':'system error please try again later'}



# 4. Delete activity by name
def delete_activity(user_input,choice):

    try:
        choice = commonplace_text(choice)
        with sqlite3.connect('activities.db') as conn:
            cursor = conn.cursor()

            if choice.lower().strip() in ['time','aika','1aikalla','bytime']:
                cursor.execute('''DELETE FROM activities WHERE fi_time = ?''', (user_input,))
                conn.commit()
                deleted = cursor.rowcount > 0
                conn.close()
            else:
                cursor.execute('DELETE FROM activities WHERE name = ?', (user_input,))
                conn.commit()
                deleted = cursor.rowcount > 0
                conn.close()
            return {'success':True,'message':deleted}
    except Exception as e:
        print(e)
        logging.error(f"get_activity error:\n",e)
        return {'success':'error','message':'system error please try again later'}




#EEH five delete activities by time
def del_act_by_time():
    try:
        with sqlite3.connect('activities.db') as conn:

            cursor = conn.cursor()

            cursor.execute('''DELETE FROM activities WHERE datetime(time_iso) < datetime(?,'-3 hours')
                           ''', (datetime.now().isoformat(),))

            conn.commit()
            deleted_count = cursor.rowcount

            return {'success': True, 'message': f'Deleted {deleted_count} finished activities'}

    except Exception as e:
        print(f"del_finished_activities error: {e}")
        return {'success': False, 'message': 'System error'}


init_db()
