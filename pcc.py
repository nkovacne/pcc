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
from postfix import mailq, release_mail, remove_mail
from netaddr import IPNetwork, IPAddress
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
            self.whitelistedips = config.get('policy', 'whitelistedips').split()
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
        # If there's no sasl_username parameter, that's probably a non-relayed attempt to send mail through the mail server
        # We won't even bother processing it, as the MTA itself will probably block the attempt
        if not params['sasl_username']:
            log.info("Not sasl_username specified, probably a non-relayed attempt, skipping")
            return self.OKCMD

        # If the user is whitelisted, there's nothing left to do
        if params['sender'] in self.whitelisted:
            log.info("Username %s is whitelisted, skipping checks" % (params['sender']))
            return self.OKCMD

        # Check whether the user is already blocked
        ses = self.session()
        is_blocked = ses.query(Blocked).filter(Blocked.username == params['sender'])
        if is_blocked.count():
            log.info("Username %s was already blocked, issuing %s on delivery" % (params['sender'], self.STOPCMD.partition(' ')[0]))
            return self.STOPCMD

        # Check whether the client IP address is amongst the ignored IP addresses or CIDR ranges
        for wip in self.whitelistedips:
            # It is a CIDR range
            if '/' in wip and IPAddress(params['client_address']) in IPNetwork(wip):
                log.debug("Client IP address %s is contained in whitelist CIDR range %s, skipping" % (params['client_address'], wip))
                return self.OKCMD
            elif wip == params['client_address']:
                log.debug("Client IP address %s is contained in whitelist list, skipping" % (params['client_address']))
                return self.OKCMD

        # Now we count how many different countries has this username sent e-mails from within the last self.days
        ses = self.session()
        countries = ses.query(Delivery).distinct(Delivery.country).filter(Delivery.sender == params['sender']).\
                    filter(and_(Delivery.valid == True, Delivery.when > datetime.now() - timedelta(days=self.days)))

        # Removing ignored countries
        for ignc in self.ignorecountries:
            countries = countries.filter(Delivery.country <> ignc)

        # If the treshold has been reached or exceeded...
        if countries.count() >= self.num_countries:
            # Block the username
            blocked_uname = Blocked(username=params['sender'])
            ses = self.session()
            ses.add(blocked_uname)
            ses.commit()

            # Notification e-mail to admins
            funcs.send_mail(to_addr=self.mailnotice.replace(' ', ','), banned=params['sender'], countries=countries, host=self.mailsrv, port=self.mailport)
            log.info("Blocking username %s due to compromised account suspicion (%d deliveries in %d days)" % (params['sender'], countries.count(), self.days))

            ses.close()
            return self.STOPCMD
        else:
            # If everything is ok, we just log the user's outgoing e-mail parameters
            match = geolite2.lookup(params['client_address'])

            # We only make the DB insertion if the country is not amongst currently configured ignored countries
            if match:
                if not match.country in self.ignorecountries:
                    log.debug("Logged outgoing e-mail %s -> %s (C: %s, IP: %s)" % (params['sender'], params['recipient'], match.country, params['client_address']))
                    delivery = Delivery(sender=params['sender'], destination=params['recipient'], country=match.country)
                    ses = self.session()
                    ses.add(delivery)
                    ses.commit()
                else:
                    log.debug("Outgoing e-mail %s -> %s: Sending from an ignored country (C: %s, IP: %s), skipping" % (params['sender'], params['recipient'], match.country, params['client_address']))
            
            ses.close()
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
                ses.delete(item)
                ses.commit()
             
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

    def cleanup(self, days):
        ses = self.session()
        todel = ses.query(Delivery).filter(Delivery.when < datetime.now() - timedelta(days=int(days)))
        total = todel.count()
        todel.delete()
        ses.commit()
        print "%d entries have been deleted from database" % (total)

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
    elif options.unblockrelease:
        pcc = PCC()
        pcc.unban(options.unblockrelease)

        held_mails = mailq(sender=options.unblockrelease)
        release_mail(held_mails)
        print "%d e-mails have been released from HOLD" % (len(held_mails))
    elif options.unblockdelete:
        pcc = PCC()
        pcc.unban(options.unblockdelete)

        held_mails = mailq(sender=options.unblockdelete)
        release_mail(held_mails)
        print "%d e-mails have been deleted from HOLD" % (len(held_mails))
    elif options.cleanup:
        pcc = PCC()
        pcc.cleanup(options.cleanup)
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
    parser.add_option("-l", "--list-blocked", dest="list_blocked", action="store_true", help="List all blocked users", default=False)
    parser.add_option("-u", "--unblock", dest="unblock", help="Simply unblock a user (and do nothing with their held emails)", default=False)
    parser.add_option("-r", "--unblockrelease", dest="unblockrelease", help="Unblock a user and release their mails from HOLD", default=False)
    parser.add_option("-e", "--unblockdelete", dest="unblockdelete", help="Unblock a user and delete their mails from HOLD", default=False)
    parser.add_option("-c", "--cleanup", dest="cleanup", help="Cleanup delivery entries older than days specified by parameter", default=False)
    options, args = parser.parse_args()

    parseopts(options)
