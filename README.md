# XSS_Test

Testing for XSS vulnerability for specific parameter(s). You can use payload file of your own with multi-parameters approach.

`python3 -m pip install beautifulsoup4`

`python3 -m pip install tqdm`

### Usage:

```
-t: target URL
-p: parameter(s)
-m: method
-c: cookie
-P: comma separated payloads
-F: payload file
```

### Examples:

```bash 
python3 xss_test.py -t "http://example-website.com/post.php" -p name -m GET -F xss-payload.txt 
```

![xss-test-1param](/xss-test-1param.png)

```py
python3 xss_test.py -t "http://example-website.com/post.php" -p name user -m GET -c "COOKIES" -P "<script>alert(1)</script>,<img src=x onerror=prompt(1)>"
```

![xss-test-2param](/xss-test-2param.png)

