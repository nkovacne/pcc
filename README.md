pcc
===

Postfix Country Control

**Description**:

  * This script is a policy service for Postfix. It is meant to be an additional check for outgoing messages, checking the client's IP address and determining their country. Bearing in mind that spammers connect to compromised (stolen) e-mail accounts using proxies and TOR servers, it is very unlikely that a user will send e-mails from more than 2 (or 3, being very cautious) different countries in a short period of time, and this is what PCC takes advantage of to determine whether an account might be compromised.
  * If a user excedes a number of sent mails from X different countries within Y days, they're put in a 'blocked' list and any further attempts to send an e-mail are REJECTed/put on HOLD (depending on configuration), until mail server administrator's intervention. Also, a list of administrators might be configured to receive notifications of blocked users.

**Version**:

  * 1.3

**Requisites**:

  * python
  * virtualenv (optional, but recommended)
  * SQLAlchemy
  * python-geoip
  * python-geoip-geolite2
  * ConfigParser
  * Additionally to the above packages, you'll have to install the package for your database backend (MySQL-python, psycopg2...)

**Configuration**:

  * pip install -r requisites.txt
  * pip install [your_database_backend]
  * Create a database and a user and grant SELECT, INSERT, UPDATE and CREATE TABLE permissions at least.
  * Copy the pcc.conf file into your /etc directory. Make sure it has reading permissions for the user running the daemon.
  * Edit your settings and adjust them to your environment. ALL parameters are mandatory. If you don't need some of them, just leave them blank (parameter =)
  * Changes to be done in Postfix:

*In your main.cf file*:

If you're running Postfix 2.10 or earlier, change your smtpd_relay_restrictions to be somewhat like this (assuming your daemon will run on port 9999):

```
smtpd_relay_restrictions =
    ....
    permit_mynetworks
    check_policy_service inet:127.0.0.1:9999
    ....
```

If you're running Postfix 2.9 or older, change your smtpd_recipient_restrictions to be somewhat like this (assuming your daemon will run on port 9999):

```
smtpd_recipient_restrictions =
    ....
    permit_mynetworks
    check_policy_service inet:127.0.0.1:9999
    ....
```

  * Finally, you just have to run your PCC daemon, supervisord is recomended (pcc.py -d).
  * You can see the available options running: pcc.py -h

**Known issues**:

  * Currently blocked users are stored in a 'username' fashion-like way (i.e., no associated domain). This may be problematic if the admin is handling more than one domain and two users with the same username but different domain are blocked and they want to unblock just one of them.
