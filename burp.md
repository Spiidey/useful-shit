# Burp Suite Stuff

CSRF Macro for Intruder

1. Capture an applicable request
2. Send to **Intruder**
3. Configure positions according to your chosen attack type (e.g. Sniper, Pitchfork)
4. Set the payload(s) in the **Payloads** tab.
5. Set up the Macro:

	5a. Go to Settings (top-right), click **Sessions**, then scroll down to **Macros** and click **Add**.
	5b. Select the request you're attacking
	5c. Now we'll have to set **Session Handling Rules**. Choose **Add*. In the details tab, give a good description, and then under **Rule Actions**, click **Add**. In the new window, select the macro we just created in 5a/5b.
	5d. 
    - Select **"Update only the following parameters and headers"**, then click the **Edit** button next to the input box below the radio button.
    - In the "Enter a new item", enter the name of the token you're grabbing. Press **Add**, then **Close**.
    - Select "Update only the following cookies", then click the relevant Edit button.
    - In the **"Enter a new item"** enter the name of the CSRF Token (*"session"*?). **Add**, then **Close**.
	- Lastly, hit **OK**.
6. Now, switch to the **Scope** tab.
7. In the "Tools Scope" section, deselect tools you *don't* want to use the macro in.
8. In "URL Scope", select **"Use suite scope"** (if you haven't set one, select **"Use custom scope"**). Now the macro only applies to things in scope.