#!/bin/bash
# Stand up OWN Elasticsearch + Kibana for authorized vuln validation (no Docker needed).
# Per Elastic HackerOne policy: reproduce on a deployment >= 1 CPU / 2 GB RAM, own account only.
# UNVERIFIED END-TO-END in the originating session (download confirmed; extraction+startup not).
# Confirm extraction + boot on first real run. Bind to 127.0.0.1 only.
set -e
ES_VER=8.15.0
LAB_DIR=/mnt/e/bugbounty/elastic.co/lab/tarball
mkdir -p "$LAB_DIR"; cd "$LAB_DIR"

echo "[*] probe + download ES"
curl -s -m 15 -r 0-1000 "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${ES_VER}-linux-x86_64.tar.gz" -o /dev/null -w "es probe: %{http_code}\n"
curl -s -m 600 -o "elasticsearch-${ES_VER}-linux-x86_64.tar.gz" "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${ES_VER}-linux-x86_64.tar.gz"
curl -s -m 600 -o "kibana-${ES_VER}-linux-x86_64.tar.gz" "https://artifacts.elastic.co/downloads/kibana/kibana-${ES_VER}-linux-x86_64.tar.gz"

echo "[*] extract"
tar xzf "elasticsearch-${ES_VER}-linux-x86_64.tar.gz"
tar xzf "kibana-${ES_VER}-linux-x86_64.tar.gz"
ES=elasticsearch-${ES_VER}; KB=kibana-${ES_VER}

echo "[*] config ES (single-node, security off, 1g heap)"
cat > "$ES/config/elasticsearch.yml" <<EOF
cluster.name: hermes-lab
node.name: hermes-node
discovery.type: single-node
xpack.security.enabled: false
network.host: 127.0.0.1
http.port: 9200
EOF
echo 'ES_JAVA_OPTS="-Xms1g -Xmx1g"' >> "$ES/config/jvm.options"

echo "[*] config Kibana"
cat > "$KB/config/kibana.yml" <<EOF
server.host: 127.0.0.1
server.port: 5601
elasticsearch.hosts: ["http://127.0.0.1:9200"]
xpack.security.enabled: false
EOF

echo "[*] start ES"
nohup "$ES/bin/elasticsearch" > ../es.log 2>&1 &
for i in $(seq 1 60); do curl -s -m 3 http://127.0.0.1:9200 >/dev/null 2>&1 && { echo "[+] ES up"; break; }; sleep 3; done

echo "[*] start Kibana"
nohup "$KB/bin/kibana" > ../kb.log 2>&1 &
for i in $(seq 1 60); do [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:5601 2>/dev/null)" = "200" ] && { echo "[+] Kibana up"; break; }; sleep 5; done

echo "[*] DONE ES=http://127.0.0.1:9200 Kibana=http://127.0.0.1:5601"
