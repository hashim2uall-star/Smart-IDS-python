import re
from collections import defaultdict
from datetime import datetime

# 1. قراءة ملف ال Log
def read_log(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    return lines

# 2. تحليل السطور واستخراج ال IPs الفاشلة
def analyze_log(lines):
    failed_attempts = defaultdict(int)
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    for line in lines:
        if "FAILED" in line or "failed" in line:
            match = re.search(ip_pattern, line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
    return failed_attempts

# 3. AI Anomaly - الكشف الذكي
def detect_anomaly(failed_attempts, threshold=3):
    alerts = []
    for ip, count in failed_attempts.items():
        if count >= threshold:
            alerts.append(f"ALERT: IP {ip} has {count} failed login attempts")
    return alerts

# 4. كتابة التقرير
def write_report(alerts, report_path):
    with open(report_path, 'w') as f:
        if alerts:
            for alert in alerts:
                f.write(alert + "\n")
        else:
            f.write("No anomalies detected\n")

# 5. التشغيل الرئيسي
if __name__ == "__main__":
    log_lines = read_log("log.txt")
    failed_ips = analyze_log(log_lines)
    alerts = detect_anomaly(failed_ips)
    write_report(alerts, "report.txt