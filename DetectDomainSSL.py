# 
# Detect SSL Domain Expired
# 
# Made by Phatnt
# 01/04/2020
# 
# Require package
# pip install pyOpenSSL
# 
# CMD: python kov_detect_domain_ssl.py -d [domain name] -f [file path contain list domain] -a [days before expired]
# EX:
# python kov_detect_domain_ssl.py -d google.com -a 30
# python kov_detect_domain_ssl.py -f domains.txt -a 30
# 
# @license MIT License
# @author phatnt <thanhphat.uit@gmail.com>
# @github https://github.com/phatnt93/python_detect_domain_ssl
# @version 1.0.0
# 

import OpenSSL
import os, sys, json, ssl, socket, argparse, smtplib
from datetime import datetime as dt
from datetime import timedelta
from os import path

class DetectDomainSSL():

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', '--domain', help = "Domain to detect expired")
        parser.add_argument('-f', '--file', help = "File contain list domain")
        parser.add_argument('-a', '--dayAlert', type = int, help = "Days before domain expired, Default : 30 days", default = 30)
        args = parser.parse_args()
        self.domain = args.domain
        self.fileDomain = args.file
        self.beforeExpired = args.dayAlert
        self.listDomain = []
        self.listDomainAlert = []
        self.dateTimeCheck = self.get_date_time_check()
        self.basePath = os.path.abspath(os.getcwd())
        self.mailConfig = self.get_mail_config()
        self.logPath = self.basePath + '/logs'
        self.log_dir()

    def get_date_time_check(self):
        return dt.now() + timedelta(days = self.beforeExpired)

    def get_mail_config(self):
        return {
            "host" : "mail.example.vn",
            "port" : "465",
            "secure" : "ssl",
            "username" : "username@example.vn",
            "password" : "password.example.vn",
            "receiver_email" : 'kov@example.vn'
        }

    def log_dir(self):
        if path.exists(self.logPath) == False:
            os.mkdir(self.logPath)

    def write_log(self, codeFlag, msg):
        flag = "Success" if codeFlag == 200 else "Error"
        now = dt.now()
        fileName = flag + "_" + now.strftime("%Y%m%d") + '.txt'
        filePath = self.logPath + "/" + fileName
        message = now.strftime("%d/%m/%Y %H:%M:%S") + ' [ ' + flag +  ' ] ' + msg + "\n"
        with open(filePath, "a") as fileLog:
            fileLog.write(message)

    def main(self):
        # Detect domain from text cmd or file
        self.get_domain();
        # Check expired domains
        self.check_ssl_expired()
        # Send email
        if len(self.listDomainAlert) > 0:
            self.send_email()
            msgLog = 'Found ' + str(len(self.listDomainAlert)) + ' expired domains (' + ",".join(self.listDomainAlert) + ')'
            self.write_log(200, msgLog)
        else:
            self.write_log(200, 'No expired domains found')

    def get_domain(self):
        if self.domain != None:
            self.listDomain.append(self.domain)
        if self.fileDomain != None:
            if path.exists(self.fileDomain) == True:
                rdomain = open(self.basePath + '/' + self.fileDomain, 'r')
                lines = rdomain.readlines()
                for line in lines:
                    self.listDomain.append(line.strip())

    def check_ssl_expired(self):
        # Has domain
        if len(self.listDomain) == 0:
            return False
        for domain in self.listDomain:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            x509info = x509.get_notAfter()
            exp_day = x509info[6:8].decode('utf-8')
            exp_month = x509info[4:6].decode('utf-8')
            exp_year = x509info[:4].decode('utf-8')
            exp_date = str(exp_day) + '-' + str(exp_month) + '-' + str(exp_year)
            if self.is_domain_will_expired(exp_date) == True:
                self.listDomainAlert.append(domain)
            # print("SSL Certificate for domain", domain, "will be expired on (DD-MM-YYYY)", exp_date)
        return True

    def is_domain_will_expired(self, exp_date):
        domainExpired = dt.strptime(exp_date, "%d-%m-%Y")
        if self.dateTimeCheck > domainExpired:
            # Must be alert domain will expire
            return True
        return False

    def send_email(self):
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(self.mailConfig.get('host'), self.mailConfig.get('port'), context=context) as server:
            server.login(self.mailConfig.get('username'), self.mailConfig.get('password'))
            server.sendmail(self.mailConfig.get('username'), self.mailConfig.get('receiver_email'), self.email_message())

    def email_message(self):
        message = "You have " + str(self.beforeExpired) + " days to renew the ssl of the domain names : \n - " + "\n - ".join(self.listDomainAlert)
        content = 'Subject: {}\n\n{}'.format('Expired domains', message)
        return content

dds = DetectDomainSSL()
dds.main()
