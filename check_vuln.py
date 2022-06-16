import argparse
from pickle import GLOBAL
from time import sleep
from fpdf import FPDF

import socket
import sys
import re
import os
import sublist3r 

import subprocess as sp
from sqlalchemy import true
from datetime import datetime
from datetime import date
today = date.today()
now = datetime.now()
current_time = now.strftime("%H:%M:%S")
daten = today.strftime("%B %d, %Y")
stg1=False
mainip=''
homedir=''
bbdomain=''
aldmn1=''
unqdmn1=''
lvdmn1=''
ports=''
services=''
exploits=''
versions=''
webatt=''

title='Scan report'

class PDF(FPDF):
    def header(self):
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Calculate width of title and position
        w = self.get_string_width(title) + 6
        self.set_x((210 - w) / 2)
        # Colors of frame, background and text
        self.set_draw_color(0, 20, 180)
        self.set_fill_color(230, 230, 0)
        self.set_text_color(220, 50, 50)
        # Thickness of frame (1 mm)
        self.set_line_width(1)
        # Title
        self.cell(w, 9, title, 1, 1, 'C', 1)
        # Line break
        self.ln(10)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Text color in gray
        self.set_text_color(128)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')

    def add_title(self, label):
        # Arial 12
        self.set_font('Arial', '', 12)
        # Background color
        self.set_fill_color(200, 220, 255)
        # Title
        self.cell(0, 6, label, 0, 1, 'L', 1)
        # Line break
        self.ln(4)

    def add_body(self, name):
        # Read text file
        with open(name, 'rb') as fh:
            txt = fh.read().decode('UTF-8')
        # Times 12
        self.set_font('Times', '', 12)
        self.multi_cell(0, 5, txt)
        

        # Line break
        self.ln()
        # Mention in italics
        self.cell(0, 5, '(end of excerpt)')

    def print_chapter(self,title, name):
        self.add_page()
        self.add_title(title)
        self.add_body(name)




def getdomain(hostname):
   try:return socket.gethostbyname(hostname)
   except: return False
            
def isValidDomain(ip):
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    p = re.compile(regex)
    if (ip == None):
        return False
    if(re.search(p, ip)):
        return True
    else:
        return False
 
def validIPAddress(IP):
    s=IP
    def isIPv4(s):
         try: return str(int(s)) == s and 0 <= int(s) <= 255
         except: return False
    def isIPv6(s):
         if len(s) > 4:
            return False
         try : return int(s, 16) >= 0 and s[0] != '-'
         except:
            return False
    try:
        if IP.count(".") == 3 and all(isIPv4(i) for i in IP.split(".")):
            return 1
    except:
        return 2
    try:
        if IP.count(":") == 7 and all(isIPv6(i) for i in IP.split(":")):
            return 1
    except:
        return 2
    return 2

def handledirs(target):
    os.system('mkdir '+ target)
    global homedir
    homedir='/'+target
    return True

def portscan(ip):
    print("*************** Nmap Scan Started*************")
    os.system('nmap -sC -sV -A  '+ip +' -Pn- -oG nmapo3.txt > /dev/null 2>&1')
    print('\n***************Nmap Scan Completed*************')
    filename='nmapo3.txt'
    f = open(filename)
    lines=f.readlines()
    portlist=lines[2]
    val=portlist.split("\t")
    nl=val[1:-1]
    listtostr=''.join([str(elem) for elem in nl])
    ns=listtostr[6:].split(",")
    filenm=ip+'.txt'
    file1 = open( filenm, 'w')
    for k in ns:
        file1.write(k)
        file1.write("\n")
    file1.close()
    global ports
    oports =sp.check_output('awk -F "/" \'{print $1}\' '+filenm , shell=True)
    rversions=sp.check_output('awk -F "/" \'{print $7}\' '+filenm , shell=True)
    rservices= sp.check_output('awk -F "/" \'{print $5}\' '+filenm , shell=True)
    prt=oports.decode("utf-8")
    prt=list(prt.split("\n"))
    ports=prt
    filename=ip+'_ports.txt'
    os.system('touch '+filename)
    file1 = open(filename, 'w')
    file1.write("ports")
    for k in prt:
   
        file1.write(k)
        file1.write("\n")
    file1.close() 
    global versions
    global services

    ver=rversions.decode("utf-8")
    ver=list(ver.split("\n"))
    versions=ver
    ser=rservices.decode("utf-8")
    ser=list(ser.split("\n"))
    
    filenm=ip+'_services.txt'
    file1 = open( filenm, 'w')
    for k in ver:
        v=k.replace('(','').replace(')','')
        file1.write(v)
        file1.write("\n")
    file1.close()

    rservices= sp.check_output('awk -F " " \'{print $1" " $2}\' '+filenm , shell=True)

    ser=rservices.decode("utf-8")
    ser=list(ser.split("\n"))
    
    print('\n\n\n***************Ports open*************')
    print("Ports")
    for k in prt:
        print(k)
    print('\n\n\n***************services and versions*************')
    services=ser
    print("services-versions")
    for k in ser:
        if len(k)>2:
            print(k)




def service_enum():
    pass

def search_vuln():
    explist=[]
    global exploits
    for k in services:
        if len(k)>2:
            print('\n seraching exploits for :' + k)
            print('searchsploit '+k)
            serres= sp.check_output('searchsploit ' +k, shell=True)
            ser=serres.decode("utf-8")
            explist.append(ser)
    
    print('\n***************Possible exploits*************')
    exploits=explist
    for k in explist:
        print(k)



def web_attacks(ip):
    global webatt
    print('\n\n***************"Trying web attacks"*************')
    os.system('uniscan -d -u '+ip)
    '''filenm=ip+'_attacks.txt'
    file1 = open( filenm, 'w')
    for v in webattacks:
        file1.write(v)
        file1.write("\n")
    file1.close()'''
    


def ctf(ip):
    global stg1
    global mainip
    if validIPAddress(ip)==1:
        stg1=true
        mainip=ip 
    elif validIPAddress(ip)==2:
        if isValidDomain(ip):
            if getdomain(ip):
                stg1=true
                mainip=getdomain(ip)
            else: print('check the domain')
        else: print('check the ip')
   
    if stg1:
        handledirs(mainip)
        portscan(mainip)
        search_vuln()
        web_attacks(ip)


        
def getsublister(bbdomain):
    print('\n***************Started Sublister*************')
    
    filenm='sublister.txt'

    subdomains = sublist3r.main(bbdomain, 40, filenm , ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)



def getassetfinder(bbdomain):
    
    print('\n***************Started assetfinder*************')
    filenm='assetfinder.txt'

    os.system('assetfinder --subs-only '+bbdomain+' >>'+filenm)


def getsubfinder(bbdomain):
 
    print('\n***************Started subfinder*************')
    os.system('subfinder -d '+bbdomain+' -o subfinder.txt')
    
def rem_noise():
    global aldmn1
    global unqdmn1
    print('\n***************Removing noise*************')
    os.system('cat assetfinder.txt sublister.txt subfinder.txt >> all_domains.txt')
    aldmn = sp.getoutput("wc -l all_domains.txt | grep -o '[0-9]\+'")
    aldmn1=aldmn
    print('subdomains aquired : '+aldmn)
    print('\n***************Removing duplicate subdomains*************')
    os.system('cat all_domains.txt| sort | uniq >> uniq_domains.txt')
    print('unique domains')
    unqdmn = sp.getoutput("wc -l uniq_domains.txt | grep -o '[0-9]\+'")
    unqdmn1=unqdmn
    print('subdomains aquired : '+unqdmn)    
    
def getlive_d():
    global lvdmn1
    print('\n***************getting live domains*************')
    os.system('cat uniq_domains.txt | httprobe >> live_domains.txt')
    lvdmn = sp.getoutput("wc -l live_domains.txt | grep -o '[0-9]\+'")
    lvdmn1=lvdmn
    print('No of live domains : '+lvdmn)  
    
        

def bugbounty(domaint):
    global bbdomain
    bbdomain=domaint
    global current_time
    global daten
    handledirs(bbdomain)
    if isValidDomain(bbdomain):
        getsublister(bbdomain)
        getassetfinder(bbdomain)
        getsubfinder(bbdomain)
        rem_noise()
        getlive_d()
        pdf = PDF()
        pdf.add_page() 
        pdf.set_title('Scan results')
        pdf.set_author('Agastya')
        pdf.add_title('Scan Date : '+daten+' Time : '+current_time)
       
        pdf.add_title('General Info')
        pdf.cell(0, 5, 'Total Domains enumrated : '+aldmn1)
        pdf.ln()
        pdf.cell(0, 5, 'Non Duplicate Domains enumrated : '+unqdmn1)
        pdf.ln()
        pdf.cell(0, 5, 'Live Domains enumrated : '+lvdmn1)
        pdf.ln()
        pdf.add_title('Domain : '+bbdomain)
        pdf.add_title('Live Domains are listed below')
        pdf.add_body('live_domains.txt')
        pdf.output(bbdomain+'_results.pdf', 'F')
    
    else:
        print('check the domain')
    





parser = argparse.ArgumentParser()
group=parser.add_mutually_exclusive_group()
parser.add_argument("-t",  help='enter the ip target of ctf challenge')
parser.add_argument("-d", help='enter the domain')
group.add_argument("-c", "--ctf", action='store_true', help="Run only ctf module")
group.add_argument("-b", "--bugbounty" ,action='store_true', help="Run only bug bounty module")

args=parser.parse_args()


if args.ctf:
    ip=args.t
    ctf(ip)
    
elif args.bugbounty:
    domaint=args.d
    bugbounty(domaint)