# Welcome to Useful-Shit/Web!

Hi! This would probably be better as a gist, honestly. But it's my repo and I'll do what I want!
This is basically just a web testing cheatsheet for me but if you find my stuff useful, a star would be appreciated😁


# Cross-Site Scripting (XSS)

XSS Payloads for fun and profit. Different types of XSS:

 - **Reflected Server XSS:** often found in locations where user input is sent via GET parameters.
	 - `search.php?s=%3Cscript%3Ealert%280%29%3C%2Fscript%3E`
 - **Stored Server XSS:** Literally stored on the server. Think user comments or blog/page posts.
	 - `<script>alert(0)</script>`
 - **Reflected Client XSS:** Same kind of idea as the Server XSS. Stuff some junk into a parameter and see what sticks.
	 - `<img src='x' onerror='alert(1)'>`
 - **Stored Client XSS:** Things like form elements can be taken advantage of to store XSS, for example a survey page for Jarrod has the URL `http://survey.tld/?name=Jarrod` and after filling the survey we end up with a new parameter `http://survey.tdl/?name=Jarrod&result`. The answers to the survey could be prone to injection, and should be tested.
