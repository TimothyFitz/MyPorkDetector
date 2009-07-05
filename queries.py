from tcpip import read_packets, collapse_tcp_streams, uint16, uint64,read1string
from itertools import islice, chain
from sql_parser import Sql
from cPickle import loads, dumps

def mysql_packetizer():
    h1 = yield
    while True:
        h2 = yield
        h3 = yield
        pn = yield
        packet_len = (h3<<24) + (h2<<8) + h1        
        data = ""
        for n in xrange(packet_len):
            data += chr((yield))

        h1 = yield (pn, data)
        
def send(iter, data):
    for c in data:
        result = iter.send(ord(c))
        if result:
            yield result
            
commands = {
    0: 'COM_SLEEP',
    1: 'COM_QUIT',
    2: 'COM_INIT_DB',
    3: 'COM_QUERY',
    4: 'COM_FIELD_LIST',
    5: 'COM_CREATE_DB',
    6: 'COM_DROP_DB',
    7: 'COM_REFRESH',
    8: 'COM_SHUTDOWN',
    9: 'COM_STATISTICS',
    10: 'COM_PROCESS_INFO',
    11: 'COM_CONNECT',
    12: 'COM_PROCESS_KILL',
    13: 'COM_DEBUG',
    14: 'COM_PING',
    15: 'COM_TIME',
    16: 'COM_DELAYED_INSERT',
    17: 'COM_CHANGE_USER',
    18: 'COM_BINLOG_DUMP',
    19: 'COM_TABLE_DUMP',
    20: 'COM_CONNECT_OUT',
    21: 'COM_REGISTER_SLAVE',
    22: 'COM_STMT_PREPARE',
    23: 'COM_STMT_EXECUTE',
    24: 'COM_STMT_SEND_LONG_DATA',
    25: 'COM_STMT_CLOSE',
    26: 'COM_STMT_RESET',
    27: 'COM_SET_OPTION',
    28: 'COM_STMT_FETCH'
}

def lcb(string):
    first = ord(string[0])
    if first <= 250:
        return first
    elif first == 251:
        return None # null
    elif first == 252:        
        return read1string(uint16, string[1:3])
    elif first == 253:
        raise "Didn't implement uint24 because bleh"
    elif first == 254:
        return read1string(uint64, string[1:9])

class MysqlQuery(object):
    def __init__(self, sql, ts):
        self.sql = sql
        self.timestamp = ts
        self.field_response = 0
        self.first_result = 0
        self.last_result = 0

class BadDataException(Exception):
    pass

conns = 0
class MysqlConnection(object):
    
    def __init__(self, onQuery = lambda *args, **kw: None):
        global conns
        conns +=1
        self.conn = conns
        self.to_server = mysql_packetizer()
        self.from_server = mysql_packetizer()
        self.to_server.next()
        self.from_server.next() 

        self.protocol = self.saw_mysql_packet()
        self.protocol.next()
        
        self.onQuery = onQuery
        
    def saw_packet(self, packet):
        if not self.protocol:
            return
            
        if packet.destination[1] == 3306:
            dir = 'to_server'
        elif packet.destination[1] != 3306:
            dir = 'from_server'
            
        for pn, data in send(getattr(self, dir), packet.data):
            mysql_packet = {'dir': dir, 'num':pn, 'data':data, 'packet': packet, 'first': ord(data[0])}
            try:
                self.protocol.send(mysql_packet)
            except (BadDataException, AssertionError):
                self.protocol = None
                break
                
        
    def saw_mysql_packet(self):
        
        internal_num = 0
        
        # handshake init
        packet = yield
        assert packet['dir'] == 'from_server'
        
        # client auth
        packet = yield
        assert packet['dir'] == 'to_server'
        
        # server response to auth
        packet = yield
        assert packet['dir'] == 'from_server'
        
        MYSQL_EOF = 0xFE
        MYSQL_OK = 0x00
        MYSQL_ERROR = 0xFF
        
        self.num = 0
        def check(dir):            
            if packet['dir'] != dir or packet['num'] != self.num % 0x100:
                raise BadDataException((
                    self.num,
                    self.conn,
                    packet))
            self.num += 1
            
        # commands!
        while True:
            # command
            self.num = 0
            packet = yield          
            check('to_server')

            command = commands[packet['first']]
            if command == 'COM_QUERY':
                query = MysqlQuery(packet['data'][1:], packet['packet'].timestamp)

            def is_eof(packet):
                return packet['first'] == 0xFE and len(packet['data']) < 9
            
            packet = yield
            check('from_server')
            
            # OK or Error, no further responses
            if packet['first'] in (MYSQL_OK, MYSQL_ERROR):
                continue
            
            query.field_response = packet['packet'].timestamp
            
            # Otherwise it's a field-count packet
            field_count = lcb(packet['data'])
            
            for n in range(field_count):
                packet = yield
                check('from_server')
            
            packet = yield
            check('from_server')
            assert is_eof(packet)
            
            first = True
            results = 0
            while True:
                packet = yield
                check('from_server')
                
                if first:
                    query.first_result = packet['packet'].timestamp
                    first = False
                
                if is_eof(packet):
                    break
                results += 1
                
            query.last_result = packet['packet'].timestamp
            query.result_size = results
            self.onQuery(query)

class Bucket(object):
    def __init__(self):
        self.data = {}
        
    def dump(self):
        return dumps(self.data)
        
    def load(self, string):
        data_to_merge = loads(string)
        for key, value in data_to_merge.items():
            self.data.setdefault(key, [])
            self.data[key].extend(value)
        
    def increment(self, item, amount = 1):
        self.data.setdefault(item, [])
        self.data[item].append(amount)
        
    def aggregate(self, item):
        data = self.data[item]
        data.sort()
        median =data[len(data) // 2]
        total = sum(data)
        count = len(data)
        
        return total, total / float(count), count, median
        
    def counts(self):
        items = [(k, self.aggregate(k)) for k in self.data.keys()]
        items.sort(key = lambda (k,(s,a,c,m)): -s)
        return [(k, s, a, c, m) for (k,(s,a,c,m)) in items]
        
import sys
count_progress = 0
def progress():
    global count_progress, total
    count_progress += 1
    if count_progress % 1000 == 0:
        sys.stdout.write('.')
        if count_progress % 20000 == 0:
            sys.stdout.write(str(total))
            sys.stdout.write('\n')

def find_mac(input):
    packets = islice(read_packets(input), 25000)
    buffer = []
    macs = Bucket()
    for n in range(200):
        read = packets.next()
        buffer.append(read)
        macs.increment(read.raw_data[0:6])
        macs.increment(read.raw_data[6:12])
    
    freq = macs.counts()
    return freq[0][0]
    
MY_MAC = '\x00\x19\xb9\xbe\x1cM'

total = 0
def main():   
    input = 'really-big-dump.bin'
    
    timing_bucket = Bucket()
    result_bucket = Bucket()
    
    
    def onQuery(query):
        global total
        time = query.first_result - query.timestamp
        sql = Sql(query.sql)
        timing_bucket.increment(sql, time)
        result_bucket.increment(sql, query.result_size)
        total += 1
    
    def ConnFactory():
        return MysqlConnection(onQuery)
    
    collapse_tcp_streams(read_packets(input), ConnFactory, progress)
    
    print total
    
    for sql, time, avg_time, count, median_time in timing_bucket.counts():
        total_rows, avg_rows, count_rows, median_rows = result_bucket.aggregate(sql)
        """
        print 'time:', time, 'avg:', avg_time, 'median:', median_time, 'count:', count, 
        print 'total rows:', total_rows, 'avg rows:', avg_rows,
        print 'sql:', sql.fuzzy()
        print sql.sql
        """
        
def timed(fn):
    from time import time
    before = time()
    fn()
    after = time()
    print 'Total time:', after - before
        
import unittest

class TestBucket(unittest.TestCase):
    
    def test_merge(self):
        a = Bucket()
        b = Bucket()
        
        a.increment('foo', 2)
        a.increment('foo', 5)
        b.increment('foo', 8)
        
        c = Bucket()
        c.load(a.dump())
        c.load(b.dump())
        
        self.assertEqual([('foo', 15, 5, 3,5)], c.counts())
        

if __name__ == "__main__":
    timed(main)
    """
    import cProfile
    cProfile.run('main()', 'profile')
    """
    
    




