# -*- coding: utf-8 -*-

from smtplib import SMTP
import socket

def send_mail(to_addr, banned, countries, host, port):
    hostname = socket.gethostname()

    smtp = SMTP()
    smtp.connect(host, port)
    from_addr = "pcc@" + hostname
    countrylist = []

    for country in countries:
      countrylist.append(country.country)

    subj = "User %s has been banned due to suspicion of compromised account" % banned

    message_text = "User %s has been banned on %s due to suspicion of compromised account\n\nList of countries: %s\n" % (banned, hostname, countrylist)

    msg = "From: %s\nTo: %s\nSubject: %s\n\n%s" % (from_addr, to_addr, subj, message_text)

    smtp.sendmail(from_addr, to_addr, msg)

def notify_unban(to_addr, host, port, user, unbanned, released=False, deleted=False):
    if (not unbanned) and (isinstance(released, bool) and not released) and (isinstance(deleted, bool) and not deleted):
        return False

    hostname = socket.gethostname()

    smtp = SMTP()
    smtp.connect(host, port)
    from_addr = "pcc@" + hostname
    countrylist = []

    subj = ""
    message_text = ""

    if unbanned:
      subj = "User ban release (%s)" % user
      message_text = "User %s has been unbanned on %s by an administrador\n" % (user, hostname)
    else:
      subj = "Messages on hold messages managed"
      message_text = "Messages on hold on %s have been managed by an administrator\n" % (hostname)

    if not isinstance(released, bool):
        message_text += "Released mails: %d\n" % (released)
    
    if not isinstance(deleted, bool):
        message_text += "Deleted mails: %d\n" % (deleted)

    msg = "From: %s\nTo: %s\nSubject: %s\n\n%s" % (from_addr, to_addr, subj, message_text)

    smtp.sendmail(from_addr, to_addr, msg)
