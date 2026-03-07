#!/bin/bash
# ===== EVIDENCE COLLECTION SCRIPT =====
# Chạy script này ngay khi phát hiện incident

INCIDENT_ID="${1:-INC-$(date +%Y%m%d-%H%M%S)}"
EVIDENCE_DIR="evidence/${INCIDENT_ID}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "=========================================="
echo "EVIDENCE COLLECTION - ${INCIDENT_ID}"
echo "Timestamp: ${TIMESTAMP}"
echo "=========================================="

# Tạo thư mục evidence
mkdir -p "${EVIDENCE_DIR}"/{logs,database,network,screenshots}

# 1. Thu thập Web Server Logs
echo "[1/6] Collecting web server logs..."
docker cp dvwa:/var/log/apache2/access.log "${EVIDENCE_DIR}/logs/apache_access.log" 2>/dev/null
docker cp dvwa:/var/log/apache2/error.log "${EVIDENCE_DIR}/logs/apache_error.log" 2>/dev/null
docker logs dvwa > "${EVIDENCE_DIR}/logs/dvwa_container.log" 2>&1

# 2. Thu thập Database Logs
echo "[2/6] Collecting database logs..."
docker exec dvwa cat /var/log/mysql/general.log > "${EVIDENCE_DIR}/database/mysql_general.log" 2>/dev/null
docker exec dvwa mysqldump -u root -p'' dvwa > "${EVIDENCE_DIR}/database/db_snapshot.sql" 2>/dev/null

# 3. Thu thập Wazuh Alerts
echo "[3/6] Collecting SIEM alerts..."
curl -s "http://localhost:9200/wazuh-alerts-*/_search?size=1000&q=rule.groups:web" \
    > "${EVIDENCE_DIR}/logs/wazuh_alerts.json" 2>/dev/null

# 4. Network Capture (5 phút)
echo "[4/6] Starting network capture (60 seconds)..."
timeout 60 docker exec dvwa tcpdump -w /tmp/capture.pcap -c 1000 2>/dev/null &

# 5. System State
echo "[5/6] Capturing system state..."
docker exec dvwa netstat -tlnp > "${EVIDENCE_DIR}/network/connections.txt" 2>/dev/null
docker exec dvwa ps aux > "${EVIDENCE_DIR}/logs/processes.txt" 2>/dev/null

# 6. Tạo evidence manifest
echo "[6/6] Creating evidence manifest..."
cat > "${EVIDENCE_DIR}/manifest.json" << EOF
{
    "incident_id": "${INCIDENT_ID}",
    "collection_time": "${TIMESTAMP}",
    "collector": "$(whoami)",
    "files": [
        $(find "${EVIDENCE_DIR}" -type f | sed 's/.*/"&"/' | paste -sd',')
    ]
}
EOF

# Tạo checksum cho integrity
echo "Generating checksums..."
find "${EVIDENCE_DIR}" -type f -exec sha256sum {} \; > "${EVIDENCE_DIR}/checksums.sha256"

echo ""
echo "=========================================="
echo "Evidence collection complete!"
echo "Location: ${EVIDENCE_DIR}"
echo "Files collected: $(find ${EVIDENCE_DIR} -type f | wc -l)"
echo "=========================================="