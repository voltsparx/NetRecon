import socket


def _whois_query(server, query, timeout=4.0):
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(2048)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="ignore")


def _extract_key_fields(text):
    keys = (
        "registrar",
        "registry expiry date",
        "expiration date",
        "expiry date",
        "name server",
        "country",
        "org",
        "organization",
    )
    extracted = []
    for line in text.splitlines():
        low = line.lower()
        if ":" not in line:
            continue
        if any(low.startswith(f"{key}:") for key in keys):
            extracted.append(line.strip())
        if len(extracted) >= 12:
            break
    return extracted


def run(target, open_ports, services):
    if all(ch.isdigit() or ch == "." for ch in target):
        query = target
    else:
        query = target.split(":", 1)[0]

    try:
        iana_data = _whois_query("whois.iana.org", query)
        refer = None
        for line in iana_data.splitlines():
            if line.lower().startswith("refer:"):
                refer = line.split(":", 1)[1].strip()
                break
        final_data = iana_data
        if refer:
            final_data = _whois_query(refer, query)

        key_fields = _extract_key_fields(final_data)
        preview = "\n".join(final_data.splitlines()[:18])
        detail_text = preview if preview else "WHOIS query returned no data."
        if key_fields:
            detail_text = "\n".join(key_fields[:12])
        return {
            "severity": "Low",
            "details": detail_text,
        }
    except Exception as exc:
        return {"severity": "Low", "details": f"WHOIS lookup failed: {exc}"}
