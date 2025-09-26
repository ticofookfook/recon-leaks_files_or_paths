import re

SECRETS_PATTERNS_STRINGS = [
    r'Basic [A-Za-z0-9+/]{15}',
    r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    r'[fF][aA][cC][eE][bB][oO][oO][kK].{0,30}[\'\"\s][0-9a-f]{32}[\'\"\s]',
    r'[tT][wW][iI][tT][tT][eE][rR].{0,30}[\'\"\s][0-9a-zA-Z]{35,44}[\'\"\s]',
    r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    r'key-[0-9a-zA-Z]{32}',
    r'[0-9a-f]{32}-us[0-9]{1,2}',
    r'sk_live_[0-9a-z]{32}',
    r'[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com',
    r'AIza[0-9A-Za-z-_]{35}',
    r'6L[0-9A-Za-z-_]{38}',
    r'ya29\\.[0-9A-Za-z\\-_]+',
    r'AKIA[0-9A-Z]{16}',
    r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    r's3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com',
    r'EAACEdEose0cBA[0-9A-Za-z]+',
    r'key-[0-9a-zA-Z]{32}',
    r'SK[0-9a-fA-F]{32}',
    r'AC[a-zA-Z0-9_\\-]{32}',
    r'AP[a-zA-Z0-9_\\-]{32}',
    r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
    r'sq0csp-[ 0-9A-Za-z\\-_]{43}',
    r'sqOatp-[0-9A-Za-z\\-_]{22}',
    r'sk_live_[0-9a-zA-Z]{24}',
    r'rk_live_[0-9a-zA-Z]{24}',
    r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*',
    r'-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----',
    r'-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----',
    r'(?i)["\']?twilio[_-]?token["\']?[^\\S\r\n]*[=:][^\\S\r\n]*["\']?[\w-]+["\']?',
    r'(?i)["\']?twilio[_-]?sid["\']?[^\\S\r\n]*[=:][^\\S\r\n]*["\']?[\w-]+["\']?',
    r'(?i)["\']?twilio[_-]?configuration[_-]?sid["\']?[^\\S\r\n]*[=:][^\\S\r\n]*["\']?[\w-]+["\']?',
    r'(?i)["\']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service["\']?[^\\S\r\n]*[=:][^\\S\r\n]*["\']?[\w-]+["\']?',
    r'(?i)["\']?twilio[_-]?api[_-]?secret["\']?[^\\S\r\n]*[=:][^\\S\r\n]*["\']?[\w-]+["\']?',
    r'(?i)["\']?twilio[_-]?api[_-]?key["\']?[^\\S\r\n]*[=:][^\\S\r\n]*["\']?[\w-]+["\']?'
    r'(https?|ftp)://[^:]+:[^@]+@[^\s]+',
    r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+',
    r'postgres://[^:]+:[^@]+@[^\s]+',
    r'mysql://[^:]+:[^@]+@[^\s]+',
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    r'AKIA[0-9A-Z]{16}',
    r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
    r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}["\']?',

]

SECRETS_PATTERNS = [re.compile(pattern) for pattern in SECRETS_PATTERNS_STRINGS]














    
