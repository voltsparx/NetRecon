import subprocess

def detect_os(target):
    try:
        ping = subprocess.Popen(["ping", "-c", "1", target], stdout=subprocess.PIPE)
        output = ping.communicate()[0].decode()
        for line in output.split("\n"):
            if "ttl=" in line.lower():
                ttl = int(line.lower().split("ttl=")[1].split()[0])
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return f"Unknown TTL={ttl}"
    except:
        pass
    return "Unknown"
