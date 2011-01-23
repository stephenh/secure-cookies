
A library for setting HMAC'd cookies.

IIRC:

    username|expiration|(data)k|HMAC(username|expiration|data|session key, k)
    where k=HMAC(user name|expiration time, sk) 
  
Maven Repo
----------

[http://repo.joist.ws](http://repo.joist.ws)

Credits
-------

Generously released as open source by [Bizo](http://www.bizo.com).

