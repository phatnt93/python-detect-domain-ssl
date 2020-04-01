# Detect SSL Domain Expired

Made by Phatnt

01/04/2020

Require package
pip install pyOpenSSL

CMD: python kov_detect_domain_ssl.py -d [domain name] -f [file path contain list domain] -a [days before expired]
EX:
python kov_detect_domain_ssl.py -d google.com -a 30
python kov_detect_domain_ssl.py -f domains.txt -a 30

@license MIT License
@author phatnt <thanhphat.uit@gmail.com>
@github https://github.com/phatnt93/python_detect_domain_ssl
@version 1.0.0
