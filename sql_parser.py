from tcpip import EOD
   
class Stream(object):
    def __init__(self, source):
        self.source = source
        self.pos = 0
        
    def peek(self, n=0):
        if self.pos >= len(self.source):
            return '\x00'
        return self.source[self.pos + n]
        
    def pull(self):
        if self.pos >= len(self.source):
            raise EOD()
        self.pos += 1
        return self.source[self.pos - 1]

def lexer(sql):
    stream = Stream(sql)
    while True:
        try:
            char = stream.pull()
        except EOD:
            return
            
        if char in whitespace:
            continue
            
        elif char in letters:
            # Tokens
            result = char
            while stream.peek() in letters+digits+'_.':
                result += stream.pull()
            if result.lower() in keywords:
                result_type = 'keyword'
                result = result.upper()
            else:
                result_type = 'token'
            yield (result_type, result)
            
        elif char in digits:
            # Numbers
            result = char
            while stream.peek() in digits+'.':
                result += stream.pull()
            yield ('number', result)
            
        elif char in punctuation:
            # Symbols
            if char == '/' and stream.peek() == '*':
                # Comments
                comment = char + stream.pull()
                while True:
                    char = stream.pull()
                    comment += char
                    if char == '*' and stream.peek() == '/':
                        comment += stream.pull()
                        yield ('comment', comment)
                        break
            elif char == "'" or char == '"' or char == '`':
                # Quoted string
                quote = char
                result = char
                while stream.peek() != quote or result[-1] == "\\":
                    result += stream.pull()
                    
                result += stream.pull()
                if quote == '`':
                    yield ('token', result)
                else:
                    yield ('string', result)
                
            else:
                # Operators, parens, etc
                if char == '!' and stream.peek() == '=':
                    yield ('symbol', char + stream.pull())
                else:
                    yield ('symbol', char)


def fuzzy(tokens):
    result = []
    last_value = None
    for key, value in tokens:
        key, value = fuzzy_token(key, value)
        if key == None:
            continue
            
        if value == ',':
            continue
            
        if value == '?' == last_value:
            continue
            
        last_value = value
            
        result.append((key, value))
    
    return result

def fuzzy_token(key, value):
    if key == 'number':
        return (key, '?')
    elif key == 'string':
        return (key, '?')
    elif key == 'comment':
        return None, None
    return (key, value)
        
    

class Sql(object):
    def __init__(self, sql):
        self.sql = sql
        self.tokens = list(lexer(sql))
        self.keywords = [tv for (tt,tv) in self.tokens if tt == 'keyword']
        try:
            self.type = self.keywords[0]
        except:
            print sql
            print self.tokens
            raise
        
        parser = getattr(self, 'parse_' + self.type, lambda: None)
            
        self.fuzzy_cache = None
            
    @property
    def tables(self):
        if self.type == 'SELECT':
            start = self.tokens.index(SELECT)
            try:
                end = self.tokens.index(WHERE, start)
            except ValueError:
                end = -1
            return [value for (tt, value) in self.tokens[start:end] if tt == 'token']
        return []
            
    def __hash__(self):
        return hash(self.key())
            
    def __cmp__(self, other):
        return cmp(self.key(), other.key())
        
    def __str__(self):
        return " ".join([value for (tt, value) in self.tokens])
        
    def fuzzy(self):
        if not self.fuzzy_cache:
            self.fuzzy_cache = " ".join([value for (tt, value) in fuzzy(self.tokens)])
        return self.fuzzy_cache
    
    key = fuzzy
    

def parse_mysql(packets):
    "deprecated"
    for packet in packets:
        header = p.data[:4]
        h1, h2, h3, pn = [ord(n) for n in header]
        packet_len = (h3<<24) + (h2<<8) + h1
        type = p.data[4]
        
        if packet_len > 3000:
            print len(data), repr(data)
        
        if dst_port == 3306 and read1string(type, uint8) == 3:
            yield (src, dst, 'query', data[5:])
        elif src_port == 3306:
            yield (dst, src, 'response')
            
    
from string import letters, digits, punctuation, whitespace

keywords = [
    'select', 'count', 'from', 'where', 'and', 
    'or', 'insert', 'update', 'concat', 'if',
    'as', 'left', 'join', 'inner', 'outer',
    'on', 'like', 'limit',  'distinct', 'set',
    'autocommit', 'ignore', 'into', 'ifnull',
    'rollback', 'begin', 'commit', 'delete', 
    'replace', 'min', 'max', 'date_sub', 'asc',
    'values', 'in', 'now', 'unix_timestamp',
    'order', 'duplicate', 'current_timestamp', 
    'by', 'group', 'key', 'desc', 'interval', 
    'rand', 'day', 'hour', 'using', 'found_rows',
    'sql_calc_found_rows', 'from_unixtime',
    'between', 'for', 'minute', 'offset', 'second',
    'show', 'full', 'processlist'
]

for keyword in keywords:
    globals()[keyword.upper()] = ('keyword', keyword.upper())
            

import unittest

class TestSQLLexer(unittest.TestCase):
    realSql = '/* Crons */ /*shard db://nrt-readonly */ SELECT COUNT(*) as count FROM customers WHERE customers_id = 39 /* /catalog/admin-scripts/crons/trigger_messages.php */'

    def test_easy_sql(self):
        sql = 'SELECT COUNT(*) FROM customers WHERE customers_id = 39'
        data = list(lexer(sql))
        expected = [
            ('keyword', 'SELECT'), 
            ('keyword', 'COUNT'), 
            ('symbol', '('), 
            ('symbol', '*'),
            ('symbol', ')'), 
            ('keyword', 'FROM'), 
            ('token', 'customers'), 
            ('keyword', 'WHERE'), 
            ('token', 'customers_id'), 
            ('symbol', '='), 
            ('number', '39')
        ]
    
        self.assertDataEqual(expected, data)
        
    def assertDataEqual(self, expected, actual):
        for left, right in zip(expected, actual):
            self.assertEqual(left, right)
        
    def test_sql_comments(self):
        commentsSql = '/* Crons */ /*shard db://nrt-readonly */ SELECT'
        
        data = list(lexer(commentsSql))
        expected = [
            ('comment', '/* Crons */'), 
            ('comment', '/*shard db://nrt-readonly */'), 
            ('keyword', 'SELECT')
        ]
        
        self.assertDataEqual(expected, data)

    def test_sql_strings(self):
        sql = "where logical_uri = 'customer://15691664'"
        data = list(lexer(sql))
        expected = [
            ('keyword', 'WHERE'), 
            ('token', 'logical_uri'), 
            ('symbol', '='), 
            ('string', "'customer://15691664'")
        ]
        self.assertDataEqual(expected, list(lexer(sql)))
        
    def test_sql_escaped_strings(self):
        sql = r"escaped_data = 'foo \' bar' and"
        data = list(lexer(sql))
        expected = [
            ('token', 'escaped_data'), 
            ('symbol', '='),
            ('string', r"'foo \' bar'"), 
            ('keyword', 'AND')
        ]
        self.assertDataEqual(expected, data)

if __name__ == "__main__":
    unittest.main()