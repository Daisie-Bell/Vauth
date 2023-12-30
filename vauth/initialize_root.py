from redis_om import Migrator

from vauth import VAuth

# Running migrations
Migrator().run()
try:
    VAuth().add_group("root", [""])
    VAuth().add_user("root", ["*"])
except Exception as e:
    print(e)
    pass
