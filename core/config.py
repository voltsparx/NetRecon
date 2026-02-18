DEFAULT_PORTS = "1-1024"

# Scanner behavior
MIN_THREADS = 20
MAX_THREADS = 300
DEFAULT_THREADS = 160
TIMEOUT = 1.2
RETRIES = 1
DEFAULT_RATE_LIMIT = 0.0

# Timing controls (used for stealth/adaptive jitter)
STEALTH_DELAY_RANGE = (0.05, 0.25)
SCAN_JITTER_RANGE = (0.0, 0.08)

# Host discovery
HOST_DISCOVERY_THREADS = 128
DISCOVERY_TIMEOUT = 1.5

# Output folders
OUTPUT_DIR_CLI = "output/cli"
OUTPUT_DIR_HTML = "output/html"
OUTPUT_DIR_JSON = "output/json"

# HTTP probing
COMMON_WEB_PORTS = [80, 81, 443, 444, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8888]
HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
    "Gecko/20100101 Firefox/123.0",
]

# Service/risk references
HIGH_RISK_PORTS = {21, 23, 69, 445, 1433, 2375, 3306, 3389, 5900, 6379, 9200}
RISK_LEVELS = ("Safe", "Low", "Medium", "High", "Critical")

TOP_COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 137, 138, 139, 143, 161, 179,
    389, 443, 445, 465, 500, 514, 515, 520, 587, 636, 989, 990, 993, 995, 1433, 1521,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2483, 2484, 3000, 3128,
    3306, 3389, 3690, 4000, 4444, 4567, 4711, 4712, 5000, 5432, 5601, 5672, 5900, 5985,
    5986, 6000, 6379, 6667, 7001, 7002, 8000, 8008, 8009, 8080, 8081, 8086, 8087, 8088,
    8089, 8090, 8181, 8200, 8333, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9418, 9999,
    10000,
]
