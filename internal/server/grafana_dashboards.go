package server

// Grafana dashboard JSON definition for file-based provisioning.
// Written to /var/lib/grafana/dashboards/ during container setup.
// File-based provisioning expects the bare dashboard object (no "dashboard" wrapper).
// Datasource references use the provisioned UID "victoriametrics".

// OverviewDashboard is a single consolidated Grafana dashboard.
const OverviewDashboard = `{
  "id": null,
  "uid": "containarium-overview",
  "title": "Containarium Overview",
  "tags": ["containarium"],
  "timezone": "browser",
  "refresh": "30s",
  "time": { "from": "now-1h", "to": "now" },
  "panels": [
    {
      "id": 1, "title": "CPUs", "type": "stat",
      "gridPos": { "h": 4, "w": 4, "x": 0, "y": 0 },
      "targets": [{ "expr": "system_cpu_count", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "blue", "value": null }] } }, "overrides": [] }
    },
    {
      "id": 2, "title": "Running", "type": "stat",
      "gridPos": { "h": 4, "w": 4, "x": 4, "y": 0 },
      "targets": [{ "expr": "containarium_containers_running", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "green", "value": null }] } }, "overrides": [] }
    },
    {
      "id": 3, "title": "Stopped", "type": "stat",
      "gridPos": { "h": 4, "w": 4, "x": 8, "y": 0 },
      "targets": [{ "expr": "containarium_containers_stopped", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "orange", "value": null }] } }, "overrides": [] }
    },
    {
      "id": 4, "title": "Memory", "type": "gauge",
      "gridPos": { "h": 4, "w": 6, "x": 12, "y": 0 },
      "targets": [{ "expr": "system_memory_used_bytes / system_memory_total_bytes * 100", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100, "thresholds": { "steps": [{ "color": "green", "value": null }, { "color": "yellow", "value": 70 }, { "color": "red", "value": 90 }] } }, "overrides": [] }
    },
    {
      "id": 5, "title": "Disk", "type": "gauge",
      "gridPos": { "h": 4, "w": 6, "x": 18, "y": 0 },
      "targets": [{ "expr": "system_disk_used_bytes / system_disk_total_bytes * 100", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100, "thresholds": { "steps": [{ "color": "green", "value": null }, { "color": "yellow", "value": 70 }, { "color": "red", "value": 90 }] } }, "overrides": [] }
    },
    {
      "id": 6, "title": "CPU Load", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 0, "y": 4 },
      "targets": [
        { "expr": "system_cpu_load_1m",  "legendFormat": "1m",  "refId": "A" },
        { "expr": "system_cpu_load_5m",  "legendFormat": "5m",  "refId": "B" },
        { "expr": "system_cpu_load_15m", "legendFormat": "15m", "refId": "C" }
      ],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 10 }, "unit": "short" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 7, "title": "Memory Over Time", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 12, "y": 4 },
      "targets": [
        { "expr": "system_memory_used_bytes",  "legendFormat": "Used",  "refId": "A" },
        { "expr": "system_memory_total_bytes", "legendFormat": "Total", "refId": "B" }
      ],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 10 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 8, "title": "Container CPU (cores)", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 0, "y": 10 },
      "targets": [{ "expr": "rate(container_cpu_usage_seconds{container_name!~\"containarium-core-.*\"}[5m])", "legendFormat": "{{ container_name }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "short" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 9, "title": "Container Memory", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 12, "y": 10 },
      "targets": [{ "expr": "container_memory_usage_bytes{container_name!~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 10, "title": "Container Disk", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 0, "y": 16 },
      "targets": [{ "expr": "container_disk_usage_bytes{container_name!~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 11, "title": "Container Network I/O", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 12, "y": 16 },
      "targets": [
        { "expr": "container_network_rx_bytes{container_name!~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }} RX", "refId": "A" },
        { "expr": "container_network_tx_bytes{container_name!~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }} TX", "refId": "B" }
      ],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 12, "title": "Core Infrastructure", "type": "row",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 22 },
      "collapsed": true,
      "panels": [
        {
          "id": 13, "title": "Core CPU (cores)", "type": "timeseries",
          "gridPos": { "h": 6, "w": 12, "x": 0, "y": 23 },
          "targets": [{ "expr": "rate(container_cpu_usage_seconds{container_name=~\"containarium-core-.*\"}[5m])", "legendFormat": "{{ container_name }}", "refId": "A" }],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "short" }, "overrides": [] },
          "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
        },
        {
          "id": 14, "title": "Core Memory", "type": "timeseries",
          "gridPos": { "h": 6, "w": 12, "x": 12, "y": 23 },
          "targets": [{ "expr": "container_memory_usage_bytes{container_name=~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }}", "refId": "A" }],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
          "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
        },
        {
          "id": 15, "title": "Core Disk", "type": "timeseries",
          "gridPos": { "h": 6, "w": 12, "x": 0, "y": 29 },
          "targets": [{ "expr": "container_disk_usage_bytes{container_name=~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }}", "refId": "A" }],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
          "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
        },
        {
          "id": 16, "title": "Core Network I/O", "type": "timeseries",
          "gridPos": { "h": 6, "w": 12, "x": 12, "y": 29 },
          "targets": [
            { "expr": "container_network_rx_bytes{container_name=~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }} RX", "refId": "A" },
            { "expr": "container_network_tx_bytes{container_name=~\"containarium-core-.*\"}", "legendFormat": "{{ container_name }} TX", "refId": "B" }
          ],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
          "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
        }
      ]
    }
  ],
  "schemaVersion": 39,
  "templating": { "list": [] },
  "annotations": { "list": [] }
}`
