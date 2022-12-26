# XSS_Test

```bash
██╗░░██╗░██████╗░██████╗████████╗███████╗░██████╗████████╗
╚██╗██╔╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
░╚███╔╝░╚█████╗░╚█████╗░░░░██║░░░█████╗░░╚█████╗░░░░██║░░░
░██╔██╗░░╚═══██╗░╚═══██╗░░░██║░░░██╔══╝░░░╚═══██╗░░░██║░░░
██╔╝╚██╗██████╔╝██████╔╝░░░██║░░░███████╗██████╔╝░░░██║░░░
╚═╝░░╚═╝╚═════╝░╚═════╝░░░░╚═╝░░░╚══════╝╚═════╝░░░░╚═╝░░░
                                                  hum4ng0d
```

Testing for XSS vulnerability for specific parameter. You can use payload file of your own. 

![xss_test](xss_test.png)

`python3 -m pip install beautifulsoup4`

`python3 -m pip install tqdm`

### Usage:

```
-t: target URL
-p: parameter
-m: method
-H: cookie
-P: comma separated payloads
-f: payload file
```

### Example:

```bash 
python3 xss_test.py -t "http://example-website.com/post.php" -f xss-payload.txt -p "name" -m GET -H "COOKIES"
```

