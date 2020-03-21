import argparse
import sys
import requests
from bs4 import BeautifulSoup
import os 

args = argparse.ArgumentParser()
args.add_argument("one")
args.add_argument("two")
all_args = args.parse_args()
ffile_name=all_args.two
print(ffile_name)
hadres=all_args.two
uurrll=all_args.two

        
def scan_file():
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'

        params = {'apikey': 'api key here'}

        files = {'file': (str(ffile_name), open(str(ffile_name), 'rb'))}

        response = requests.post(url, files=files, params=params)

        deger=(response.json()["permalink"])
        print("Ayrıntılı sonuç: {}".format(deger))

        url =  str(deger)
        response =  requests.get(url) 
        html_icerigi = response.content  
        soup =  BeautifulSoup(html_icerigi,"html.parser")
        a = soup.find("table",id="antivirus-results").text
        print(a)
        print(deger)
def scan_url():
        urlurl = 'https://www.virustotal.com/vtapi/v2/url/scan'

        paramsurl = {'apikey': 'api key here', 'url':(uurrll)}

        responseurl = requests.post(urlurl, data=paramsurl)

        degerurl=(responseurl.json()["permalink"])
        print(degerurl)

        urll= str(degerurl)
        responseurll= requests.get(urll)
        html_urll = responseurll.content
        soupurll =  BeautifulSoup(html_urll,"html.parser")
        aurll=soupurll.find("table",id="scanning-results").text
        print(aurll)

def hashcontrol():
        hash_directory=input("Hash degerini sorgulamak istediğiniz dosyanın dizinini giriniz(ismiyle birlikte): ")
        str(os.system("sha256sum {}".format(hash_directory)))        

j=0
while j<1:
        if ffile_name[0]=="/":
                scan_file()
        elif uurrll.startswith=="http":
                scan_url()
        elif hadres.startswith=="/":
                hashcontrol()
        else:
                print("1 dakika sonra yeniden deneyin:/")
        j+=1
