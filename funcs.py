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
