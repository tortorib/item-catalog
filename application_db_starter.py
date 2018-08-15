#!/usr/bin/python2.7

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from application_db_setup import Sport, Base, RecentlyAdded, User

engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# Create dummy user
User1 = User(name="Ben Tortorice", email="tortorib@gmail.com",
             picture='https://pbs.twimg.com/profile_images/919545422263259137/y3kfPP4a.jpg')  # noqa
session.add(User1)
session.commit()

# Football items
sport1 = Sport(user_id=1, name="Football")

session.add(sport1)
session.commit()

recently_added1 = RecentlyAdded(user_id=1, name="Youth Football Helmet",
                              description="Help protect your star player\'s \
                                head as he faces tough opponents.",
                              price="$15.00",
                              sport=sport1)

session.add(recently_added1)
session.commit()


recently_added2 = RecentlyAdded(name="Football", user_id=1,
                              description="Real Leather. ",
                              price="$12.99",
                              sport=sport1)

session.add(recently_added2)
session.commit()




print("Added catalog items!")
