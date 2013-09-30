import util
import sqlite3
import config

""" Manages all interactions between zarp and the connected database
"""


class Database(object):
    def __init__(self):
        self.connection = None

        db_type = config.get('db_con')
        if db_type == 'sqlite3':
            self.connection = sqlite3.connect('config/zarp.db',
                                                check_same_thread=False)
        elif db_type == 'pgsql':
            util.Error('Postgres is not yet supported.')
        elif db_type == 'mysql':
            util.Error('mysql is not yet supported')

    def initialize_schema(self):
        """ If this is a new db, build it
        """
        tmp = insert('create table log(module, time, message)')
        if not tmp:
            return

        # it didnt fail, create default schema
        insert('create table host (mac UNIQUE, ip, hostname);')
        insert('create table credentials (username, password, location, '
               'source_idx, time, FOREIGN KEY(source_idx) REFERENCES host(ROWID));')

db = None


def initialize():
    global db
    db = Database()
    db.initialize_schema()


def fetch(query, parameters=None):
    """ Generic fetch query.  Returns a list of all results.

        Parameters should be a tuple, or list of tuples.
        ie: SELECT ? FROM log;
            parameters = ('module',)
    """
    global db
    try:
        cursor = db.connection.cursor()

        if parameters is None:
            cursor.execute(query)
        else:
            cursor.execute(query, parameters)
        return cursor.fetchall()
    except Exception, e:
        print e
        return None


def insert(query, parameters=None):
    """ Generic insert/create/update query against the loaded database.
    """
    global db
    success = False
    try:
        cursor = db.connection.cursor()

        if parameters is None:
            cursor.execute(query)
        else:
            cursor.execute(query, parameters)

        db.connection.commit()
        success = True
    except:
        success = False    # unique violation/doesnt exist/etc.
    return success


def shutdown():
    """ Commit any cached queries and close down the connection
    """
    global db
    if db is not None:
        db.connection.commit()
        db.connection.close()


def _timestamp():
    """ return a formatted timestamp
    """
    return util.timestamp()


def dblog(msg, module):
    """ Insert a log event.  Removes a newline.
    """
    return insert('INSERT INTO log VALUES (?,?,?)', (module, _timestamp(),
                                                            msg.rstrip()))


def dbcredentials(username, password, location, source):
    """ Insert credentials into the database.

        Source should be an IP address of the source the credentials were
        coming from.
        Location is where the credentials were being used at.
    """
    source_idx = fetch('SELECT ROWID FROM host WHERE ip = ?', (source,))[0][0]
    if source_idx is not None:
        return insert('INSERT INTO credentials VALUES (?,?,?,?,?)',
                    (username, password, location, source_idx, _timestamp()))


def dbhost(mac, ip, hostname):
    """ insert basic host information into the database
    """
    return insert('INSERT INTO host VALUES (?,?,?);', (mac, ip, hostname))
