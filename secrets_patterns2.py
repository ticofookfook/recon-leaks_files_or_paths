import re

SECRETS_PATTERNS_STRINGS = [
    # ===== TOKENS DE API GENÉRICOS =====
    r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'["\']?private[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'Bearer\s+[a-zA-Z0-9_\-\.]+',
    r'Basic\s+[A-Za-z0-9+/]{20,}={0,2}',
    
    # ===== PASSWORDS E CREDENCIAIS =====
    r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    r'["\']?passwd["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    r'["\']?pwd["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    r'["\']?db[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    r'["\']?database[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    
    # ===== URLs COM CREDENCIAIS =====
    r'(http?|ftp)://[^:]+:[^@]+@[^\s]+',
    r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+',
    r'postgres://[^:]+:[^@]+@[^\s]+',
    r'mysql://[^:]+:[^@]+@[^\s]+',
    
    # ===== JWT TOKENS =====
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    
    # ===== AWS =====
    r'AKIA[0-9A-Z]{16}',
    r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
    r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}["\']?',
    
    # ===== GOOGLE/GCP =====
    r'AIza[0-9A-Za-z_-]{35}',
    r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    r'ya29\.[0-9A-Za-z_-]+',
    r'service_account["\']?\s*[:=]\s*\{[^}]*"private_key"[^}]*\}',
    
    # ===== GITHUB =====
    r'gh[opsu]_[A-Za-z0-9_]{36}',
    r'github[_-]?token["\']?\s*[:=]\s*["\']?gh[opsu]_[A-Za-z0-9_]{36}["\']?',
    
    # ===== SLACK =====
    r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}',
    r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    
    # ===== STRIPE =====
    r'sk_live_[0-9a-zA-Z]{24,}',
    r'pk_live_[0-9a-zA-Z]{24,}',
    r'rk_live_[0-9a-zA-Z]{24,}',
    
    # ===== FIREBASE =====
    r'[a-z0-9]{0,30}\.firebaseio\.com',
    r'[a-z0-9]{0,30}\.firebaseapp\.com',
    
    # ===== PRIVATE KEYS =====
    r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
    
    # ===== OAUTH =====
    r'client[_-]?secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    r'client[_-]?id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    
    # ===== DISCORD =====
    r'discord[_-]?token["\']?\s*[:=]\s*["\']?[MN][a-zA-Z0-9_\-]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}["\']?',
    r'discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
    
    # ===== TELEGRAM =====
    r'[0-9]{9,10}:[a-zA-Z0-9_-]{35}',
    
    # ===== SENDGRID =====
    r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    
    # ===== MAILGUN =====
    r'key-[a-f0-9]{32}',
    r'[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}',
    
    # ===== PAYPAL =====
    r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    
    # ===== SQUARE =====
    r'sq0atp-[0-9A-Za-z_-]{22}',
    r'sq0csp-[0-9A-Za-z_-]{43}',
    
    # ===== HEROKU =====
    r'[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    
    # ===== FACEBOOK =====
    r'EAACEdEose0cBA[0-9A-Za-z]+',
    r'facebook.*["\']?[0-9a-f]{32}["\']?',
    
    # ===== TWITTER =====
    r'twitter.*["\']?[0-9a-zA-Z]{35,44}["\']?',
    
    # ===== LINKEDIN =====
    r'linkedin.*["\']?[0-9a-z]{12}["\']?',
    
    # ===== TWILIO =====
    r'AC[a-z0-9]{32}',
    r'SK[a-z0-9]{32}',
    
    # ===== DOCKER =====
    r'docker[_-]?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?',
    
    # ===== NPM =====
    r'//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9_-]+',
    
    # ===== AMBIENTE (.env patterns) =====
    r'DATABASE_URL\s*=\s*.+',
    r'DB_CONNECTION\s*=\s*.+',
    r'REDIS_URL\s*=\s*.+',
    r'MONGO_URI\s*=\s*.+',
    r'SECRET_KEY\s*=\s*.+',
    r'APP_KEY\s*=\s*.+',
    r'APP_SECRET\s*=\s*.+',
]

# Compila todos os padrões
SECRETS_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SECRETS_PATTERNS_STRINGS]
