import re

def main():
    ip_counts = {}
    ip_paths = {}

    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).+?"\w+ ([^ ]+)')

    with open("sample-log.log", "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if not match:
                continue
            ip = match.group(1)
            path = match.group(2)

            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            if ip not in ip_paths:
                ip_paths[ip] = {}
            ip_paths[ip][path] = ip_paths[ip].get(path, 0) + 1

    total_requests = sum(ip_counts.values())
    unique_ips = len(ip_counts)
    average_requests = total_requests / unique_ips

    threshold = 5 * average_requests
    anomalies = {ip: count for ip, count in ip_counts.items() if count > threshold}

    report = []
    report.append("📄 Traffic Surge Analysis Report\n")
    report.append(f"Total unique IP addresses: {unique_ips}")
    report.append(f"Total requests: {total_requests}")
    report.append(f"Average requests per IP: {average_requests:.2f}")
    report.append(f"\n🚨 IPs with more than {threshold:.2f} requests (potential anomalies):\n")

    for ip, count in anomalies.items():
        report.append(f"{ip}: {count} requests")
        report.append("  Top requested paths:")

        sorted_paths = sorted(ip_paths[ip].items(), key=lambda x: x[1], reverse=True)
        top_paths = sorted_paths[:5]
        other_count = sum(c for _, c in sorted_paths[5:])

        for path, pcount in top_paths:
            flag = ""
            if "login" in path or "signin" in path:
                flag = "⚠️  possible login attempt"
            elif "../" in path:
                flag = "⚠️  suspicious traversal"
            elif path.startswith("/admin"):
                flag = "⚠️  admin probe"
            elif path.startswith("/api"):
                flag = "API call"
            elif path.startswith("/search"):
                flag = "search activity"

            report.append(f"    {path}: {pcount} times {flag}")

        if other_count > 0:
            report.append(f"    Other paths: {other_count} requests")
        report.append("")

    with open("anomaly_report.txt", "w") as f:
        f.write("\n".join(report))

    print("✅ Report generated: anomaly_report.txt (now with correct paths!)")

if __name__ == "__main__":
    main()