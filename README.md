# Detect SSL Domain Expired
Help check ssl domain expired and send alert to email.
Version 1.0.0

## Require package
- pip install pyOpenSSL

## Start
**Command line:**
```
python DetectDomainSSL.py -d [domain name] -f [file path contain list domain] -a [days before expired]
```

**EX:**

With a domain name
```
python DetectDomainSSL.py -d google.com -a 30
```
With a file list domain name
```
python DetectDomainSSL.py -f domains.txt -a 30
```

- License MIT License
- Author phatnt <thanhphat.uit@gmail.com>
- Github https://github.com/phatnt93/python-detect-domain-ssl
