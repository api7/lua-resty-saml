import sys

with open(sys.argv[1]) as f:
    lines = f.read().splitlines()
    if len(lines) == 1:
        s = lines[0]
        lines = [s[i:i+64] for i in range(0, len(s), 64)]
        lines.insert(0, "-----BEGIN CERTIFICATE-----")
        lines.append("-----END CERTIFICATE-----")
        print("\\n".join(lines))
    else:
        print("\\n".join(lines))
