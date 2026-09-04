import re
from collections import defaultdict
from datetime import datetime

# 1. قراءة ملف الـ Log
def read_log(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    return lines

# 2. تحليل السطور واستخراج الـ IPs الفاشلة
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

# 3. الكشف الذكي - AI Anomaly
def detect_anomaly(failed_attempts):
    if not failed_attempts:
        return "No suspicious activity"
    
    avg_attempts = sum(failed_attempts.values()) / len(failed_attempts)
    alerts = []
    
    for ip, count in failed_attempts.items():
        # القاعدة الاساسية: اكتر من 3 محاولات
        # القاعدة الذكية: اكتر من ضعف المعدل
        if count >= 3 or count > avg_attempts * 2:
            alerts.append(f"ALERT: IP {ip} has {count} failed attempts")
    
    return alerts if alerts else ["System Normal"]

# 4. توليد التقرير
def generate_report(alerts):
    with open("report.txt", "w") as f:
        f.write("=== Smart IDS Report ===\n")
        f.write(f"Date: {datetime.now()}\n\n")
        for alert in alerts:
            f.write(alert + "\n")
    print("Report generated: report.txt")

# التشغيل الرئيسي
if __name__ == "__