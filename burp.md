# Burp Suite Stuff

## CSRF Macro for Intruder

Some pages, like login and contact forms, have CSRF tokens embedded as invisible parameters that are submitted to the server. These tend to change with every request made and can trip up password-guessing and brute attacks due to invalid CSRF from previously captured requests. We can create and use a macro in Burp Suite to automate updating these tokens for us.

1. Capture an applicable request

2. Set up the Macro:

3. Go to **Settings** (top-right), click **Sessions** from the menu on the left.

4. Under **"Session handling rules"** click **"Add"** and a new window opens.

5. In the "Session handling rule editor", give your rule a meaningful description, and then under **"Rule actions"** click **"Add"**, then select **"Run a macro"**. Again, a new window opens (Session handling action editor).

6. Under "Select macro", click **"Add"** and "Macro recorder" window opens. Select the request you want to attack and press **"OK"**. Now you can use the "Macro Editor" that was hidden behind the "Macro recorder" window.

7. In "Macro Editor", give your new macro a meaningful name, like "CSRF-Grabber". Click "OK" to close the editor. Now we're back to the Session handling action editor, and our macro is selected.

8. Select **"Update only the following parameters and headers"**, then click the **Edit** button next to the textbox. A new "Edit list" window appears.

9. In the *"Enter a new item"*, enter the name of the form token you're grabbing. Press **Add**, then **Close**. Click **"OK"** when done.

10. Move down to "Update current request with cookies from session handling cookie jar". Select "Update only the following cookies", then click the "Edit" button. Again, an "Edit list" window pops up.

11. In the *"Enter a new item"*, enter the name of the CSRF Token (e.g. *"session"*). **Add**, then **Close**. Hit **OK** again.

12. Now, switch to the **Scope** tab.

13. In the "Tools Scope" section, deselect tools you *don't* want to use the macro in. (I usually leave it ON for Intruder AND Repeater)

14. In "URL Scope", select **"Use suite scope"** (if you haven't set one, select **"Use custom scope"**). Now the macro only applies to things in scope.

15. Click OK to close the Session handling rules window, and close your settings window. You should be all set-up to rock and roll now.