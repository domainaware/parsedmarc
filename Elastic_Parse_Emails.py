import parsedmarc.elastic
from glob import glob
import json
import parsedmarc
import urllib
from argparse import ArgumentParser



arg_parser = ArgumentParser(description="Parses DMARC reports into elastic search")
arg_parser.add_argument("-E", "--elasticsearch-host", nargs="*",
                            help="A list of one or more Elasticsearch "
                                 "hostnames or URLs to use (Default "
                                 "localhost:9200)",
                            default=["localhost:9200"])                            
arg_parser.add_argument("-H", "--host", help="IMAP hostname or IP address")
arg_parser.add_argument("-U", "--user", help="IMAP user")
arg_parser.add_argument("-P", "--password", help="IMAP password")

args = arg_parser.parse_args()

try:
    if args.host is None or args.user is None or args.password is None:
        print("user and password must be specified if host is specified")
        print("Ex: -E localhost:9200 -H 'email.com' -U 'myemail' -P 'mypassword'  " )
except:
    print("")

datFile = urllib.request.urlopen("https://publicsuffix.org/list/public_suffix_list.dat")
with open('.public_suffix_list.dat','wb') as output:
  output.write(datFile.read())


parsedmarc.elastic.set_hosts(args.elasticsearch_host)
parsedmarc.elastic.create_indexes() 
host = args.host[0]
user = args.user[0]
password = args.password[0]     
temp = parsedmarc.parse_watched_inbox(host,user,password)
          