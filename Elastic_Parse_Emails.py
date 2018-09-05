import unittest
import parsedmarc.elastic
from glob import glob
import json
import parsedmarc
import urllib2


datFile = urllib2.urlopen("https://publicsuffix.org/list/public_suffix_list.dat")
with open('.public_suffix_list.dat','wb') as output:
  output.write(datfile.read())


  
class Test(unittest.TestCase):
    def testSamples(self):
        parsedmarc.elastic.set_hosts("localhost:9200")##set host
        parsedmarc.elastic.create_indexes()      
        temp = parsedmarc.watch_inbox("host.email.com","username","password")##set server,user,pass
        
if __name__ == "__main__":
    unittest.main(verbosity=2)
