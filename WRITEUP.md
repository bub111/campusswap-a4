# Assignment 4 Write up

## V1 SQL Injection

The login and search were just gluing whatever I typed right into the database question. So if I typed database words instead of a normal username, the database would follow them. That let me get into the hidden quartermaster account with no password, and pull everyone's username and password out of the search page. To fix it I stopped gluing the text in and instead handed it to the database as plain input. Now the database always treats what I type as just a value to look for, not as commands, so the trick stops working and normal login and search still work.

## V2 Stored XSS

Comments were being saved and then shown on the page exactly as typed. So if someone typed in a bit of script instead of a real comment, the browser would run it for everyone who opened that item, and it could even steal their login cookie. I fixed it by cleaning the comment so any script shows up as plain text instead of running. I also added a rule that tells the browser to only run scripts from our own site, and I made the login cookie hidden from page scripts so it cannot be stolen that way.

## V3 CSRF

The send credits button only checked that I had a login cookie, and the browser sends that cookie automatically even when another website asks it to. So a random bad website could secretly send a transfer using my login the moment I opened it, and my credits would be gone without me clicking anything. I fixed it by giving each login a secret random code that only exists on the real site and gets put inside the real transfer form. The site checks for that code before moving any credits, so an outside page cannot fake it. I also set the cookie so it does not get sent on requests coming from other sites. A normal transfer still works, but the fake page cannot move credits anymore.
