import unittest
import parsedmarc.elastic
from glob import glob
import json

import parsedmarc


class Test(unittest.TestCase):
    def testSamples(self):
        parsedmarc.elastic.set_hosts("localhost:9200")##set host
        parsedmarc.elastic.create_indexes()      
        temp = parsedmarc.watch_inbox("host.email.com","username","password")##set server,user,pass
        
if __name__ == "__main__":
    unittest.main(verbosity=2)
