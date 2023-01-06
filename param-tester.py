#!/usr/bin/env python3

#param-tester v1.0 by hum4ng0d
#Usage for POST request:
#python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_s/" -c "PHPSESSID=value; security=low" -m POST -F xss-quick.txt -d "txtName=s&mtxMessage=s&btnSign=Sign+Guestbook" -p txtName mtxMessage
#python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_s/" -c "PHPSESSID=value; security=low" -m POST -F xss-quick.txt -d "txtName=s&mtxMessage=s&mtxEmail=s&btnSign=Sign+Guestbook" -p txtName mtxMessage mtxEmail
#
#Usage for GET request:
#python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_r/" -c "PHPSESSID=value; security=low" -m GET -F xss-quick.txt -p name
#python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_r/" -c "PHPSESSID=value; security=low" -m GET -F xss-quick.txt -p name password email

import argparse, datetime, requests, urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from tqdm import tqdm

def color(text, color):
    colors = {
        "orange": "\033[33m",
        "reset": "\033[0m"
    }
    return f"{colors[color]}{text}{colors['reset']}"

def printBanner():
    print(color("""


██████╗░░█████╗░██████╗░░█████╗░███╗░░░███╗░░░░░░████████╗███████╗░██████╗████████╗███████╗██████╗░
██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗░████║░░░░░░╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝███████║██████╔╝███████║██╔████╔██║█████╗░░░██║░░░█████╗░░╚█████╗░░░░██║░░░█████╗░░██████╔╝
██╔═══╝░██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║╚════╝░░░██║░░░██╔══╝░░░╚═══██╗░░░██║░░░██╔══╝░░██╔══██╗
██║░░░░░██║░░██║██║░░██║██║░░██║██║░╚═╝░██║░░░░░░░░░██║░░░███████╗██████╔╝░░░██║░░░███████╗██║░░██║
╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚═╝░░░░░░░░░╚═╝░░░╚══════╝╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚═╝ v1.0
                                                                                                hum4ng0d

    """, "orange"))

current_time = datetime.datetime.now()
formatted_time = current_time.strftime("%m/%d/%Y %I:%M:%S %p")
with open('exploits.log', 'a') as f:
  f.write("\n" + formatted_time + "\n")

vuln_found = False

def send_request(url, method, payload, parameter=None, cookies=None, data=None):
  global vuln_found
  identifier = "INJECTX"

  try:
    if method.lower() == "post":
      r = requests.post(url, data=data, headers={"Cookie": cookies, "Content-Type": "application/x-www-form-urlencoded"})
    elif method.lower() == "get":
      r = requests.get(url, params={parameter: payload}, headers={"Cookie": cookies})
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    if identifier in soup.prettify():
      decoded_payload = urllib.parse.unquote_plus(payload)
      with open('exploits.log', 'a') as f:
        f.write("[+] Vulnerability found in parameter: " + parameter + ", using payload: " + decoded_payload + "\n")
      vuln_found = True
  except requests.exceptions.RequestException as e:
    print("Error:", e)

def main():
  printBanner()
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--url", required=True, help="the URL to test for XSS vulnerabilities")
  parser.add_argument("-p", "--parameters", required=True, nargs='+', help="the list of parameters to test for XSS vulnerabilities")
  parser.add_argument("-d", "--data", required=False, help="POST request data body")
  parser.add_argument("-m", "--method", required=True, help="the request method to use (GET or POST)")
  parser.add_argument("-c", "--cookies", required=False, help="the cookies header to send with the request")
  parser.add_argument("-F", "--payload_file", required=True, help="a file containing payloads to use for testing")
  args = parser.parse_args()

  parsed_url = urlparse(args.url)
  if parsed_url.scheme == "" or parsed_url.netloc == "":
    print("[-]Error: Invalid URL")
    return

  if args.method.lower() not in ["get", "post"]:
    print("[-]Error: Invalid request method")
    return

  spec_params = []
  if args.parameters:
    spec_params = args.parameters

  body_data = []
  if args.data:
    body_data = args.data.split("&")

  payloads = []
  if args.payload_file:
    try:
      with open(args.payload_file) as f:
        payloads = f.readlines()
    except IOError:
      print("[-]Error: Could not read {}".format(args.payload_file))
      return
    payloads = [x.strip() for x in payloads]
  else:
    print("[-]Error: No payload file specified")
    return

  if args.method.lower() == "post":
    for spec_param in spec_params:
      print("Testing Parameter: " + spec_param)
      if any(parameter.startswith(spec_param + "=") for parameter in body_data):
        for payload in tqdm(payloads):
          parameter = None
          modified_body_data = []
          for param in body_data:
            key, value = param.split("=")
            if key == spec_param:
              parameter = key
              payload = urllib.parse.quote_plus(payload)
              modified_body_data.append(f"{key}={payload}")
            else:
              modified_body_data.append(f"{key}={value}")
          modified_body_request = "&".join(modified_body_data)
          send_request(args.url, args.method, payload, parameter, args.cookies, modified_body_request)
      else:
        raise ValueError(f"[-]Parameter: '{spec_param}' not found in request body")
  elif args.method.lower() == "get":
    for parameter in args.parameters:
      print("Testing Parameter: " + parameter)
      for payload in tqdm(payloads):
        payload = urllib.parse.quote_plus(payload)
        send_request(args.url, args.method, payload, parameter, args.cookies)

if __name__ == "__main__":
  main()

  if not vuln_found:
    with open('exploits.log', 'a') as f:
      f.write("[-] No vulnerabilities found.\n")

  try:
    with open("exploits.log") as f:
      print(f.read())
  except IOError:
    print("Error: Could not read exploits.log")
