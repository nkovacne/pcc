# -*- coding: utf-8 -*-

from smtplib import SMTP
import socket

def send_mail(to_addr, banned, countries, host = 'localhost', port = 25):
  hostname = socket.gethostname()

  smtp = SMTP()
  smtp.connect(host, port)
  from_addr = "pcc@" + hostname
  paises = []

  for pais in countries:
    paises.append(pais.pais)

  subj = "Baneado usuario %s por sospecha de cuenta robada" % banned

  message_text = "El usuario %s ha sido baneado en %s por sospecha de cuenta robada\n\nRelacion de paises localizados: %s\n" % (banned, hostname, paises)

  msg = "From: %s\nTo: %s\nSubject: %s\n\n%s" % (from_addr, to_addr, subj, message_text)

  smtp.sendmail(from_addr, to_addr, msg)
