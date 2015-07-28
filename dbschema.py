# -*- coding: utf-8 -*-

from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, MetaData
from sqlalchemy.orm import mapper
import datetime

# Metadata object for storing DB schema
metadata = MetaData()

# Schema of the delivery table
delivery_table = Table('delivery', metadata,
    Column('id', Integer, primary_key=True, nullable=False, autoincrement=True),
    Column('when', DateTime, nullable=False, default=datetime.datetime.utcnow),
    Column('sender', String(length=100), nullable=False),
    Column('destination', String(length=100), nullable=False),
    Column('country', String(length=2), nullable=False),
    Column('valid', Boolean, nullable=False, default=True)
)

# Schema of the blocked table
blocked_table = Table('blocked', metadata,
    Column('id', Integer, primary_key=True, nullable=False, autoincrement=True),
    Column('username', String(length=100), nullable=False),
    Column('when', DateTime, nullable=False, default=datetime.datetime.utcnow)
)

# Mapping class Delivery (ORM)
class Delivery(object):
    def __init__(self, sender, destination, country):
        self.sender = sender
        self.destination = destination
        self.country = country

    def __repr__(self):
        return "<%s, %s, %s>" % (self.sender, self.destination, self.country)

# Mapping class Blocked (ORM)
class Blocked(object):
    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return "<%s>" % (self.username)

# Establishing the mapping between schema <-> class
mapper(Delivery, delivery_table)
mapper(Blocked, blocked_table)
