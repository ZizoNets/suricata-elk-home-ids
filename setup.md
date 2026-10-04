# Setup

Replace placeholders in `< >`: `<MONITOR_IFACE>` (capture interface), `<SENSOR_LAN_IP>` (sensor address).

## 1. Port mirroring

On the TP-Link managed switch, enable port mirroring in its web interface (the menu name varies by model). Mirrored ports: the ones to monitor. Mirroring port: the one connected to the sensor's capture interface.

Check that the sensor sees the traffic:

```bash
sudo tcpdump -ni <MONITOR_IFACE> -c 20
```

## 2. Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata
```

Merge [`suricata-excerpt.yaml`](../configs/suricata/suricata-excerpt.yaml) into `/etc/suricata/suricata.yaml`, then:

```bash
sudo cp configs/suricata/local.rules /etc/suricata/rules/local.rules
sudo cp configs/suricata/disable.conf /etc/suricata/disable.conf
sudo suricata-update                                  # downloads Emerging Threats Open
sudo suricata -T -c /etc/suricata/suricata.yaml -v    # validate
sudo systemctl enable --now suricata
```

## 3. Elasticsearch, Kibana and Filebeat

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch kibana filebeat
```

Apply the files in `configs/elasticsearch`, `configs/kibana` and `configs/filebeat`. Elasticsearch 8 enables security and TLS on install and prints the `elastic` password once, so save it. Keep passwords and tokens in the keystores (`kibana-keystore`, `filebeat keystore`), not in the YAML files.

```bash
sudo systemctl enable --now elasticsearch kibana
sudo filebeat modules enable suricata
sudo filebeat test config
sudo filebeat setup --pipelines --modules suricata
sudo filebeat setup --dashboards
sudo systemctl enable --now filebeat
```

## 4. Test

From another machine, against devices you own:

```bash
ping <TARGET_IP>
nmap -sS -p 1-1000 <TARGET_IP>
```

Watch the alerts live:

```bash
sudo tail -f /var/log/suricata/fast.log
```

They show up in Kibana a few seconds later.

## 5. Log rotation

Rotation is set to 72 hours. [TODO: add the config used]
