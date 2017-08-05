# emailspoofer<br>
<br>
spoofcheck.py checks for proper configuration of SPF and DMARC records<br>
spoofcheck.py has colorama and emailprotectionslib and tldextract dependencies<br>
sudo pip install colorama && sudo pip install emailprotectionslib && sudo pip install tldextract <br>
usage: python ./spoofcheck.py example.com<br>
<br>
<br>
spammer.py is an email spoofing program that is still in development, but is functional<br>
<br>
spammer.py requires an smtp server to function. I am using postfix (sudo apt-get install postfix -y)<br>
<br>
spammer.py has the same dependencies as spoofcheck.py otherwise<br>
sudo pip install colorama && sudo pip install emailprotectionslib && sudo pip install tldextract <br>
<br>
usage instructions: python ./spammer.py --help <br>
usage: spammer.py [-h] [-t TO_ADDRESS] [-a TO_ADDRESS_FILENAME] <br>
                  [-f FROM_ADDRESS] [-n FROM_NAME] [-c] [-j SUBJECT] <br>
                  [-e EMAIL_FILENAME] [--important] [-i] [-r REPLY_TO] <br>
                  [--image IMAGE] [--attach ATTACHMENT_FILENAME] [--track] <br>
                  [-d DB_NAME] [-s SMTP_SERVER] [-p SMTP_PORT] [--slow]<br>
<br>
optional arguments: <br>
  -h, --help            show this help message and exit<br>
<br>
Email Options:<br>
  -t TO_ADDRESS, --to TO_ADDRESS<br>
                        Email address to send to<br>
  -a TO_ADDRESS_FILENAME, --to_address_filename TO_ADDRESS_FILENAME<br>
                        Filename containing a list of TO addresses<br>
  -f FROM_ADDRESS, --from FROM_ADDRESS <br>
                        Email address to send from<br>
  -n FROM_NAME, --from_name FROM_NAME<br>
                        From name<br>
  -c, --check           Check if sender domain is spoofable<br>
  -j SUBJECT, --subject SUBJECT<br>
                        Subject for the email<br>
  -e EMAIL_FILENAME, --email_filename EMAIL_FILENAME<br>
                        Filename containing an HTML email<br>
  --important           Send as a priority email<br>
  -i, --interactive     Input email in interactive mode<br>
  -r REPLY_TO, --reply-to REPLY_TO<br>
                        Set a reply-to header<br>
  --image IMAGE         Attach an image<br>
  --attach ATTACHMENT_FILENAME<br>
                        Attach a file<br>
<br>
Email Tracking Options:<br>
  --track               Track email links with GUIDs<br>
  -d DB_NAME, --db DB_NAME<br>
                        SQLite database to store GUIDs<br>
<br>
SMTP options:<br>
  -s SMTP_SERVER, --server SMTP_SERVER<br>
                        SMTP server IP or DNS name (default localhost)<br>
  -p SMTP_PORT, --port SMTP_PORT<br>
                        SMTP server port (default 25)<br>
  --slow                Slow the sending<br><br>
  
