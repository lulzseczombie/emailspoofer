#! /usr/bin/env python
 
 
import re
import smtplib
import argparse
import logging
import sqlite3
import uuid
import time
import random
import sys
 
import mimetypes
 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email import encoders
from colorama import Fore, Back, Style
from colorama import init as color_init
import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib
import logging
 
 
global db
 
def output_good(line):
    print Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL, line
 
def output_indifferent(line):
    print Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line
 
def output_error(line):
    print Fore.RED + Style.BRIGHT + "[-] !!! " + Style.NORMAL, line, Style.BRIGHT + "!!!"
 
def output_bad(line):
    print Fore.RED + Style.BRIGHT + "[-]" + Style.RESET_ALL, line
 
def output_info(line):
    print Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line
   
def check_spf_redirect_mechanisms(spf_record):
    redirect_domain = spf_record.get_redirect_domain()
 
    if redirect_domain is not None:
        output_info("Processing an SPF redirect domain: %s" % redirect_domain)
 
        return is_spf_record_strong(redirect_domain)
 
    else:
        return False
 
def check_spf_include_mechanisms(spf_record):
    include_domain_list = spf_record.get_include_domains()
 
    for include_domain in include_domain_list:
        output_info("Processing an SPF include domain: %s" % include_domain)
 
        strong_all_string = is_spf_record_strong(include_domain)
 
        if strong_all_string:
            return True
 
    return False
 
def is_spf_redirect_record_strong(spf_record):
    output_info("Checking SPF redirect domian: %(domain)s" % {"domain": spf_record.get_redirect_domain})
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    if redirect_strong:
        output_bad("Redirect mechanism is strong.")
    else:
        output_indifferent("Redirect mechanism is not strong.")
 
    return redirect_strong
 
def are_spf_include_mechanisms_strong(spf_record):
    output_info("Checking SPF include mechanisms")
    include_strong = spf_record._are_include_mechanisms_strong()
    if include_strong:
        output_bad("Include mechanisms include a strong record")
    else:
        output_indifferent("Include mechanisms are not strong")
 
    return include_strong
 
def check_spf_include_redirect(spf_record):
    other_records_strong = False
    if spf_record.get_redirect_domain() is not None:
        other_records_strong = is_spf_redirect_record_strong(spf_record)
 
    if not other_records_strong:
        other_records_strong = are_spf_include_mechanisms_strong(spf_record)
 
    return other_records_strong
 
def check_spf_all_string(spf_record):
    strong_spf_all_string = True
    if spf_record.all_string is not None:
        if spf_record.all_string == "~all" or spf_record.all_string == "-all":
            output_indifferent("SPF record contains an All item: " + spf_record.all_string)
        else:
            output_good("SPF record All item is too weak: " + spf_record.all_string)
            strong_spf_all_string = False
    else:
        output_good("SPF record has no All string")
        strong_spf_all_string = False
 
    if not strong_spf_all_string:
        strong_spf_all_string = check_spf_include_redirect(spf_record)
 
    return strong_spf_all_string
 
def is_spf_record_strong(domain):
    strong_spf_record = True
    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record is not None and spf_record.record is not None:
        output_info("Found SPF record:")
        output_info(str(spf_record.record))
 
        strong_all_string = check_spf_all_string(spf_record)
        if strong_all_string is False:
 
            redirect_strength = check_spf_redirect_mechanisms(spf_record)
            include_strength = check_spf_include_mechanisms(spf_record)
 
            strong_spf_record = False
 
            if redirect_strength is True:
                strong_spf_record = True
 
            if include_strength is True:
                strong_spf_record = True
    else:
        output_good(domain + " has no SPF record!")
        strong_spf_record = False
 
    return strong_spf_record
 
def get_dmarc_record(domain):
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    if dmarc is not None and dmarc.record is not None:
        output_info("Found DMARC record:")
        output_info(str(dmarc.record))
    return dmarc
 
def get_dmarc_org_record(base_record):
    org_record = base_record.get_org_record()
    if org_record is not None:
        output_info("Found DMARC Organizational record:")
        output_info(str(org_record.record))
    return org_record
 
def check_dmarc_extras(dmarc_record):
    if dmarc_record.pct is not None and dmarc_record.pct != str(100):
            output_indifferent("DMARC pct is set to " + dmarc_record.pct + "% - might be possible")
 
    if dmarc_record.rua is not None:
        output_indifferent("Aggregate reports will be sent: " + dmarc_record.rua)
 
    if dmarc_record.ruf is not None:
        output_indifferent("Forensics reports will be sent: " + dmarc_record.ruf)
 
def check_dmarc_policy(dmarc_record):
    policy_strength = False
    if dmarc_record.policy is not None:
        if dmarc_record.policy == "reject" or dmarc_record.policy == "quarantine":
            policy_strength = True
            output_bad("DMARC policy set to " + dmarc_record.policy)
        else:
            output_good("DMARC policy set to " + dmarc_record.policy)
    else:
        output_good("DMARC record has no Policy")
 
    return policy_strength
 
def check_dmarc_org_policy(base_record):
    policy_strong = False
 
    try:
        org_record = base_record.get_org_record()
        if org_record is not None and org_record.record is not None:
            output_info("Found organizational DMARC record:")
            output_info(str(org_record.record))
 
            if org_record.subdomain_policy is not None:
                if org_record.subdomain_policy == "none":
                    output_good("Organizational subdomain policy set to %(sp)s" % {"sp": org_record.subdomain_policy})
                elif org_record.subdomain_policy == "quarantine" or org_record.subdomain_policy == "reject":
                    output_bad("Organizational subdomain policy explicitly set to %(sp)s" % {"sp": org_record.subdomain_policy})
                    policy_strong = True
            else:
                output_info("No explicit organizational subdomain policy. Defaulting to organizational policy")
                policy_strong = check_dmarc_policy(org_record)
        else:
            output_good("No organizational DMARC record")
 
    except dmarclib.OrgDomainException:
        output_good("No organizational DMARC record")
 
    except Exception as e:
        logging.exception(e)
 
    return policy_strong
 
def is_dmarc_record_strong(domain):
    dmarc_record_strong = False
 
    dmarc = get_dmarc_record(domain)
 
    if dmarc is not None and dmarc.record is not None:
        dmarc_record_strong = check_dmarc_policy(dmarc)
 
        check_dmarc_extras(dmarc)
    elif dmarc.get_org_domain() is not None:
        output_info("No DMARC record found. Looking for organizational record")
        dmarc_record_strong = check_dmarc_org_policy(dmarc)
    else:
        output_good(domain + " has no DMARC record!")
 
    return dmarc_record_strong
 
 
def get_args():
    parser = argparse.ArgumentParser()
 
    email_options = parser.add_argument_group("Email Options")
 
    email_options.add_argument("-t", "--to", dest="to_address", help="Email address to send to")
    email_options.add_argument("-a", "--to_address_filename", dest="to_address_filename", help="Filename containing a list of TO addresses")
    email_options.add_argument("-f", "--from", dest="from_address", help="Email address to send from")
    email_options.add_argument("-n", "--from_name", dest="from_name", help="From name")
    email_options.add_argument("-c", "--check", dest="spoofable", action="store_true", default=False, help="Check if sender domain is spoofable")
    email_options.add_argument("-j", "--subject", dest="subject", help="Subject for the email")
    email_options.add_argument("-e", "--email_filename", dest="email_filename", help="Filename containing an HTML email")
    email_options.add_argument("--important", dest="important", action="store_true", default=False, help="Send as a priority email")
    email_options.add_argument("-i", "--interactive", action="store_true", dest="interactive_email", help="Input email in interactive mode")
    email_options.add_argument("-r", "--reply-to", dest="reply_to", help="Set a reply-to header")
    email_options.add_argument("--image", action="store", dest="image", help="Attach an image")
    email_options.add_argument("--attach", action="store", dest="attachment_filename", help="Attach a file")
 
    tracking_options = parser.add_argument_group("Email Tracking Options")
    tracking_options.add_argument("--track", dest="track", action="store_true", default=False, help="Track email links with GUIDs")
    tracking_options.add_argument("-d", "--db", dest="db_name", help="SQLite database to store GUIDs")
 
    smtp_options = parser.add_argument_group("SMTP options")
    smtp_options.add_argument("-s", "--server", dest="smtp_server", help="SMTP server IP or DNS name (default localhost)", default="localhost")
    smtp_options.add_argument("-p", "--port", dest="smtp_port", type=int, help="SMTP server port (default 25)", default=25)
    smtp_options.add_argument("--slow", action="store_true", dest="slow_send", default=False, help="Slow the sending")
 
    return parser.parse_args()
 
 
def get_ack(force):
    output_info("To continue: [yes/no]")
    if force is False:
        yn = raw_input()
        if yn != "yes":
            return False
        else:
            return True
    elif force is True:
        output_indifferent("Forced yes")
        return True
    else:
        raise TypeError("Passed in non-boolean")
 
 
def get_interactive_email():
    email_text = ""
 
    # Read email text into email_text
    output_info("Enter HTML email line by line")
    output_info("Press CTRL+D to finish")
    while True:
        try:
            line = raw_input("| ")
            email_text += line + "\n"
        except EOFError:
            output_info("Email captured.")
            break
 
    return email_text
 
 
def get_file_email():
    email_text = ""
    try:
        with open(args.email_filename, "r") as infile:
            output_info("Reading " + args.email_filename + " as email file")
            email_text = infile.read()
    except IOError:
        output_error("Could not open file " + args.email_filename)
        exit(-1)
 
    return email_text
 
 
def is_domain_spoofable(from_address):
    color_init()
    spoofable = False
 
    try:
        domain = args.from_address.split('@')[1]
 
        spf_record_strength = is_spf_record_strong(domain)
 
        dmarc_record_strength = is_dmarc_record_strong(domain)
        if dmarc_record_strength is False:
            spoofable = True
        else:
            spoofable = False
 
        if spoofable:
            output_good("Spoofing possible for " + domain + "!")
        else:
            output_bad("Spoofing not possible for " + domain)
 
    except IndexError:
        output_error("Wrong domain name!")
   
    return spoofable
 
def bootstrap_db():
    global db
    db.execute("CREATE TABLE IF NOT EXISTS targets(email_address, uuid)")
    db.commit()
 
 
def save_tracking_uuid(email_address, target_uuid):
    global db
    db.execute("INSERT INTO targets(email_address, uuid) VALUES (?, ?)", (email_address, target_uuid))
    db.commit()
 
 
def create_tracking_uuid(email_address):
    tracking_uuid = str(uuid.uuid4())
    save_tracking_uuid(email_address, tracking_uuid)
    return tracking_uuid
 
 
def inject_tracking_uuid(email_text, tracking_uuid):
    TRACK_PATTERN = "\[TRACK\]"
 
    print "Injecting tracking UUID %s" % tracking_uuid
 
    altered_email_text = re.sub(TRACK_PATTERN, tracking_uuid, email_text)
    return altered_email_text
 
 
def inject_name(email_text, name):
    NAME_PATTERN = "\[NAME\]"
    print "Injecting name %s" % name
 
    altered_email_text = re.sub(NAME_PATTERN, name, email_text)
    return altered_email_text
 
 
def delay_send():
    sleep_time = random.randint(1, 55) + (60*5)
    time.sleep(sleep_time)
 
 
if __name__ == "__main__":
    global db
 
    args = get_args()
   
    if args.spoofable:
        if args.from_domain is not None:
            is_spoofable = is_domain_spoofable()
            if is_spoofable is False:
                exit(1)
    global db
    if args.track:
        if args.db_name is not None:
            db = sqlite3.connect(args.db_name)
            bootstrap_db()
        else:
            logging.error("DB name is empty")
            exit(1)
 
    email_text = ""
    if args.interactive_email:
        email_text = get_interactive_email()
    else:
        try:
            email_text = get_file_email()
        except TypeError:
            logging.error("Could not load email from file %s" % args.email_filename)
            exit(1)
 
    to_addresses = []
    if args.to_address is not None:
        to_addresses.append(args.to_address)
    elif args.to_address_filename is not None:
        try:
            with open(args.to_address_filename, "r") as to_address_file:
                to_addresses = to_address_file.readlines()
        except IOError as e:
            logging.error("Could not locate file %s", args.to_address_filename)
            raise e
    else:
        logging.error("Could not load input file names")
        exit(1)
 
    try:
        output_info("Connecting to SMTP server at " + args.smtp_server + ":" + str(args.smtp_port))
        server = smtplib.SMTP(args.smtp_server, args.smtp_port)
        msg = MIMEMultipart("alternative")
        msg.set_charset("utf-8")
 
        if args.from_name is not None:
            output_info("Setting From header to: " + args.from_name + "<" + args.from_address + ">")
            msg["From"] = args.from_name + "<" + args.from_address + ">"
        else:
            output_info("Setting From header to: " + args.from_address)
            msg["From"] = args.from_address
 
        if args.subject is not None:
            output_info("Setting Subject header to: " + args.subject)
            msg["Subject"] = args.subject
 
        if args.important:
            msg['X-Priority'] = '2'
 
        if args.reply_to is not None:
            msg['Reply-To'] = args.reply_to
 
        if args.image:
            with open(args.image, "rb") as imagefile:
                img = MIMEImage(imagefile.read())
                msg.attach(img)
 
        for to_address in to_addresses:
            msg["To"] = to_address
 
            if args.track:
                tracking_uuid = create_tracking_uuid(to_address)
                altered_email_text = inject_tracking_uuid(email_text, tracking_uuid)
                msg.attach(MIMEText(altered_email_text, 'html', 'utf-8'))
            else:
                msg.attach(MIMEText(email_text, 'html', 'utf-8'))
 
            if args.attachment_filename is not None:
 
                ctype, encoding = mimetypes.guess_type(args.attachment_filename)
                if ctype is None or encoding is not None:
                    # No guess could be made, or the file is encoded (compressed), so
                    # use a generic bag-of-bits type.
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)
                with open(args.attachment_filename, "rb") as attachment_file:
                    inner = MIMEBase(maintype, subtype)
                    inner.set_payload(attachment_file.read())
                    encoders.encode_base64(inner)
                inner.add_header('Content-Disposition', 'attachment', filename=args.attachment_filename)
                msg.attach(inner)
 
            server.sendmail(args.from_address, to_address, msg.as_string())
            output_good("Email Sent to " + to_address)
            if args.slow_send:
                delay_send()
                output_info("Connecting to SMTP server at " + args.smtp_server + ":" + str(args.smtp_port))
                server = smtplib.SMTP(args.smtp_server, args.smtp_port)
 
    except smtplib.SMTPException as e:
        output_error("Error: Could not send email")
        raise e
