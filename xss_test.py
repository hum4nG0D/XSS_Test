import argparse
import datetime
import requests
import urllib.parse
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

██╗░░██╗░██████╗░██████╗████████╗███████╗░██████╗████████╗
╚██╗██╔╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
░╚███╔╝░╚█████╗░╚█████╗░░░░██║░░░█████╗░░╚█████╗░░░░██║░░░
░██╔██╗░░╚═══██╗░╚═══██╗░░░██║░░░██╔══╝░░░╚═══██╗░░░██║░░░
██╔╝╚██╗██████╔╝██████╔╝░░░██║░░░███████╗██████╔╝░░░██║░░░
╚═╝░░╚═╝╚═════╝░╚═════╝░░░░╚═╝░░░╚══════╝╚═════╝░░░░╚═╝░░░
                                                  hum4ng0d

    """, "orange"))

current_time = datetime.datetime.now()
formatted_time = current_time.strftime("%m/%d/%Y %I:%M:%S %p")
with open('exploits.log', 'a') as f:
  f.write("\n" + formatted_time + "\n")

def test_xss(url, payload, parameter, method, cookies):
  try:
    if method.lower() == "post":
      r = requests.post(url, data={parameter: payload}, headers={"Cookie": cookies})
    elif method.lower() == "get":
      r = requests.get(url, params={parameter: payload}, headers={"Cookie": cookies})
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    if payload in soup.prettify():
      payloads = urllib.parse.unquote_plus(payload)
      with open('exploits.log', 'a') as f:
        f.write("[+] XSS vulnerability found in parameter: " + parameter + ", using payload: " + payloads + "\n")
      return True
  except requests.exceptions.RequestException as e:
    print("Error:", e)
  return False

def main():
  # Parse the command line arguments
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--url", required=True, help="the URL to test for XSS vulnerabilities")
  parser.add_argument("-p", "--parameters", required=True, nargs='+', help="the list of parameters to test for XSS vulnerabilities")
  parser.add_argument("-m", "--method", required=True, help="the request method to use (GET or POST)")
  parser.add_argument("-c", "--cookies", required=False, help="the cookie headers to send with the request")
  parser.add_argument("-P", "--payloads", required=False, help="a comma-separated list of payloads to use for testing")
  parser.add_argument("-F", "--payloads_file", required=True, help="a file containing payloads to use for testing")
  args = parser.parse_args()

  parsed_url = urlparse(args.url)
  if parsed_url.scheme == "" or parsed_url.netloc == "":
    print("Error: Invalid URL")
    return

  if args.method.lower() not in ["get", "post"]:
    print("Error: Invalid request method")
    return

  if args.payloads:
    payloads = args.payloads.split(",")
  elif args.payloads_file:
    try:
      with open(args.payloads_file) as f:
        payloads = f.readlines()
    except IOError:
      print("Error: Could not read {}".format(args.payloads_file))
      return
    payloads = [x.strip() for x in payloads]
  else:
    print("Error: No payloads specified")
    return

  for parameter in args.parameters:
    print("Testing Parameter: " + parameter)
    counter = 0
    for items in tqdm(payloads):
      payload = urllib.parse.quote_plus(items)
      counter += 1
      test_xss(args.url, payload, parameter, args.method, args.cookies)


if __name__ == "__main__":
  main()

  try:
    with open("exploits.log") as f:
      print(f.read())
  except IOError:
    print("Error: Could not read exploits.log")
