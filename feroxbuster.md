Taken from the [README.md on feroxbuster GitHub](https://github.com/epi052/feroxbuster/blob/af3dcdf6a24bf137256cfa6ffc3eff07c5a6eadd/README.md).

## 🧰 Example Usage

Here are a few brief examples to get you started.  Please note, feroxbuster can do a **lot more** than what's listed below.  As a result, there are **many more** examples, with **demonstration gifs** that highlight specific features, in the [documentation](https://epi052.github.io/feroxbuster-docs/docs/).

### Multiple Values

Options that take multiple values are very flexible. Consider the following ways of specifying extensions:

```
./feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx
```

The command above adds .pdf, .js, .html, .php, .txt, .json, and .docx to each url

All of the methods above (multiple flags, space separated, comma separated, etc...) are valid and interchangeable. The
same goes for urls, headers, status codes, queries, and size filters.

### Include Headers

```
./feroxbuster -u http://127.1 -H Accept:application/json "Authorization: Bearer {token}"
```

### IPv6, non-recursive scan with INFO-level logging enabled

```
./feroxbuster -u http://[::1] --no-recursion -vv
```

### Read urls from STDIN; pipe only resulting urls out to another tool

```
cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files
```

### Proxy traffic through Burp

```
./feroxbuster -u http://127.1 --insecure --proxy http://127.0.0.1:8080
```

### Proxy traffic through a SOCKS proxy (including DNS lookups)

```
./feroxbuster -u http://127.1 --proxy socks5h://127.0.0.1:9050
```

### Pass auth token via query parameter

```
./feroxbuster -u http://127.1 --query token=0123456789ABCDEF
```


