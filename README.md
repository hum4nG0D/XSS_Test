# param-tester.py

Yet another script for testing a given parameter(s) with a specified payload file. It will url-encode the payload list before sending the request and will print out url-decoded payload. The results will be saved in the file `exploits.log`. For multiple parameters, it will run through one parameter at a time and you will be able to see it in the progress bar. You can specify GET or POST request.

You can change the payload identifier for vulnerability checking in the response.

```
identifier = "INJECTX"
```

### Requirements

`python3 -m pip install beautifulsoup4`

`python3 -m pip install tqdm`

### Usage:

```
-t: target URL
-p: parameter(s) - multiple parameters using space
-m: method
-c: cookies
-d: request body data
-F: payload file path
```

### Examples:

```bash 
python3 param-tester.py -t "http://example-website.com/testing/" -p name -m GET -F xss-payload.txt 

python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_r/" -c "PHPSESSID=value; security=low" -m GET -F xss-quick.txt -p name

```

![param-tester-get](/param-tester-get.png)

```bash
python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_s/" -c "PHPSESSID=value; security=low" -m POST -F xss-quick.txt -d "txtName=s&mtxMessage=s&btnSign=Sign+Guestbook" -p txtName mtxMessage

python3 param-tester.py -t "http://192.168.11.11:1335/vulnerabilities/xss_s/" -c "PHPSESSID=value; security=low" -m POST -F xss-quick.txt -d "txtName=s&mtxMessage=s&mtxEmail=s&btnSign=Sign+Guestbook" -p txtName mtxMessage mtxEmail

```

![param-tester-post](/param-tester-post.png)

### Future improvements:

- Verification of the found vulnerability (XSS, SQLi)
- Payload generation
