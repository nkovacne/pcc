#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import SocketServer
import ConfigParser
from sqlalchemy import create_engine, exc, and_
from sqlalchemy.orm import sessionmaker
import logging
import funcs
from datetime import datetime, timedelta
from dbschema import Delivery, Blocked, metadata
from geoip import geolite2
from optparse import OptionParser
import os.path
from logging.handlers import SysLogHandler

# Configuration file path
configpath = '/etc/pcc.conf'

# logger object handler
log = logging.getLogger('pcc')
log.setLevel(logging.INFO)
syslog = SysLogHandler('/dev/log', facility = SysLogHandler.LOG_MAIL)
syslog.setFormatter(logging.Formatter('%(name)s: %(levelname)s %(message)s'))
log.addHandler(syslog)

class PCCAbstract(object):
    """
      This class is the global definition of the PCC script.
      It will read the configuration file (/etc/pcc.conf) and
      make the server run and listen on the specified port.
    """

    # Postfix commands
    OKCMD = "DUNNO"

    def load_config(self):
        # Configuration loading
        config = ConfigParser.ConfigParser()
        config.read(configpath)

        try:
            self.dbcon = config.get('db', 'dbcon')
            self.domains = config.get('mail', 'domains').split()
            self.mailnotice = config.get('mail', 'notice')
            self.mailsrv = config.get('mail', 'mailsrv')
            self.mailport = config.get('mail', 'mailport')
            self.num_countries = int(config.get('policy', 'how_many_different_countries'))
            self.days = int(config.get('policy', 'in_how_much_time_in_days'))
            self.ignorecountries = config.get('policy', 'ignorecountries').split()
            self.whitelisted = config.get('policy', 'whitelisted').split()
            self.reason = config.get('policy', 'reason')
            self.STOPCMD = config.get('policy', 'action')
        except ConfigParser.NoOptionError, e:
            print "ERROR: %s" % (e)
            sys.exit(4)

        if self.reason:
            self.STOPCMD += " %s" % self.reason

        # Establishment of the connection with the database
        try:
            connection = create_engine(self.dbcon, pool_size=10)
        except Exception, e:
            print "Error while attempting to connect to the database (%s): %s'" % (self.dbcon, e)
            sys.exit(3)

        metadata.create_all(connection, checkfirst=True)

        self.session = sessionmaker(bind=connection)

        return True

    def __init__(self):
        self.load_config()

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, debug=True):
        self.load_config()
        SocketServer.BaseRequestHandler.__init__(self, server_address, RequestHandlerClass, bind_and_activate) 
    
class TCPHandler(PCCAbstract, SocketServer.BaseRequestHandler):
    """
      TCP handler whose 'handle' method will pick up an outgoing
      Postfix's e-mail parameters and analyze them
    """

    def process_country(self, params):
        # If the user is whitelisted, there's nothing left to do
        if params['sasl_username'] in self.whitelisted:
            log.info("Username %s is whitelisted, skipping checks" % (params['sasl_username']))
            return self.OKCMD

        # Check whether the user is already blocked
        ses = self.session()
        is_blocked = ses.query(Blocked).filter(Blocked.username == params['sasl_username'])
        if is_blocked.count():
            log.info("Username %s was already blocked, issuing %s on delivery" % (params['sasl_username'], self.STOPCMD.partition(' ')[0]))
            return self.STOPCMD

        # Now we count how many different countries has this username sent e-mails from within the last self.days
        ses = self.session()
        countries = ses.query(Delivery).filter(Delivery.sender == params['sasl_username']).\
                    filter(and_(Delivery.valid == True, Delivery.when > datetime.now() - timedelta(days=self.days)))

        # Removing ignored countries
        for ignc in self.ignorecountries:
            countries = countries.filter(Delivery.country <> ignc)

        # If the treshold has been reached or exceeded...
        if countries.count() >= self.num_countries:
            # Block the username
            blocked_uname = Blocked(username=params['sasl_username'])
            ses = self.session()
            ses.add(blocked_uname)
            ses.commit()

            # Notification e-mail to admins
            funcs.send_mail(to_addr=",".join(self.mailnotice), banned=params['sasl_username'], countries=countries, host=self.mailsrv, port=self.mailport)
            log.info("Blocking username %s due to compromised account suspicion (%d deliveries in %d days)" % (params['sasl_username'], self.days))

            return self.STOPCMD
        else:
            # If everything is ok, we just log the user's outgoing e-mail parameters
            match = geolite2.lookup(params['client_address'])

            # We only make the DB insertion if the country is not amongst currently configured ignored countries
            if match:
                if not match.country in self.ignorecountries:
                    log.debug("Logged outgoing e-mail %s -> %s (C: %s, IP: %s)" % (params['sasl_username'], params['recipient'], match.country, params['client_address']))
                    delivery = Delivery(sender=params['sasl_username'], destination=params['recipient'], country=match.country)
                    ses = self.session()
                    ses.add(delivery)
                    ses.commit()
                else:
                    log.debug("Outgoing e-mail %s -> %s: Sending from an ignored country (C: %s, IP: %s), skipping" % (params['sasl_username'], params['recipient'], match.country, params['client_address']))
    
            return self.OKCMD

    # Once we receive parameters via TCP, we'll have to process them
    def handle(self):
        params = { } 
        paramlist = self.request.recv(65535).strip().split('\n')

        # We'll create a dictorionary with any key <-> value pair
        for pair in paramlist:
            parts = pair.split('=')
            params[parts[0]] = parts[1]

        log.debug("Outgoing e-mail parameters received: %s" % params)

        # We're just interested in outgoing e-mails listed in the self.domains parameter
        dom = params['sender'].split('@')
        try:
            if dom[1] in self.domains:
                result = self.process_country(params)
                log.debug("Returning policy: %s" % result)
                self.request.sendall("action=%s\n\n" % result)
            else:
                log.debug("Domain %s is not listed in config, skipping" % dom[1])
                self.request.sendall("action=%s\n\n" % self.OKCMD)
        except IndexError:
            log.debug("Empty sender, skipping")
            self.request.sendall("action=%s\n\n" % self.OKCMD)

        log.debug("---------------------------")

class PCC(PCCAbstract):
    """
      This class inherits from PCCAbstract and implements some additional methods (unblock, etc.)
    """

    def __init__(self):
        super(PCC, self).load_config()

    def unban(self, user):
        ses = self.session()
        blocked = ses.query(Blocked).filter(Blocked.username == user)

        if not blocked.count():
            print "ERROR: Username %s is not currently blocked" % (user)
        else:
            for item in blocked:
                ses = self.session()
                ses.delete(item)
                ses.commit()
             
            ses = self.session()
            invalidate = ses.query(Delivery).filter(Delivery.when > datetime.now() - timedelta(days=self.days))
            for row in invalidate:
               row.valid = False
               ses.commit()
               log.info("Unblocking user '%s' on demand" % user);
               print "Unblock: Username %s has been unblocked" % (user)

    def list_banned(self):
        ses = self.session()
        blocked = ses.query(Blocked).all()

        if (not blocked):
            print "There are no blocked users at this time"
        else:
            print " "
            for user in blocked:
                print "Blocked: %s" % (user.username)
            print " "
            print "Total blocked: %d" % (len(blocked))

def run_server():
    """
      Function that invokes the daemon version
    """

    config = ConfigParser.ConfigParser()
    config.read(configpath)

    # We create the server listening on the post you specified in the configuration file
    server = SocketServer.TCPServer((config.get('server', 'host'), int(config.get('server', 'port'))), TCPHandler)

    # Listen forever
    server.serve_forever()

def parseopts(options):
    """
      Function that parses the specified options by the user and takes the corresponding action
    """

    if options.daemon:
        run_server()
    elif options.unblock:
        pcc = PCC()
        pcc.unban(options.unblock)
    elif options.list_blocked:
        pcc = PCC()
        pcc.list_banned()
    else:
        if options.verbose:
            log.setLevel(logging.DEBUG)
        run_server()

if __name__ == "__main__":
    if not os.path.exists(configpath):
        print "ERROR: There's no configuration file (%s)" % (configpath);
        sys.exit(1)

    config = ConfigParser.ConfigParser()
    try:
        config.read(configpath)
    except IOError:
        print "ERROR: There's no configuration file or it hasn't the appropriate read permissions (%s)" % (configpath);
        sys.exit(2)

    parser = OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode. Debugging lines are written to mail log.", default=False)
    parser.add_option("-d", "--daemon", dest="daemon", action="store_true", help="Daemon mode", default=False)
    parser.add_option("-u", "--unblock", dest="unblock", help="Unblock a user", default=False)
    parser.add_option("-l", "--list-blocked", dest="list_blocked", action="store_true", help="List all blocked users", default=False)
    options, args = parser.parse_args()

    parseopts(options)
