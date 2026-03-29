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
      "id": 21, "title": "Node Metrics", "type": "row",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 0 },
      "collapsed": false
    },
    {
      "id": 1, "title": "Total CPUs", "type": "stat",
      "gridPos": { "h": 4, "w": 4, "x": 0, "y": 1 },
      "targets": [{ "expr": "sum(system_cpu_count{backend_id=~\"$backend\"})", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "blue", "value": null }] } }, "overrides": [] }
    },
    {
      "id": 2, "title": "Running", "type": "stat",
      "gridPos": { "h": 4, "w": 4, "x": 4, "y": 1 },
      "targets": [{ "expr": "sum(containarium_containers_running{backend_id=~\"$backend\"})", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "green", "value": null }] } }, "overrides": [] }
    },
    {
      "id": 3, "title": "Stopped", "type": "stat",
      "gridPos": { "h": 4, "w": 4, "x": 8, "y": 1 },
      "targets": [{ "expr": "sum(containarium_containers_stopped{backend_id=~\"$backend\"})", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "orange", "value": null }] } }, "overrides": [] }
    },
    {
      "id": 4, "title": "Memory", "type": "gauge",
      "gridPos": { "h": 4, "w": 6, "x": 12, "y": 1 },
      "targets": [{ "expr": "system_memory_used_bytes{backend_id=~\"$backend\"} / system_memory_total_bytes{backend_id=~\"$backend\"} * 100", "legendFormat": "{{ backend_id }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100, "thresholds": { "steps": [{ "color": "green", "value": null }, { "color": "yellow", "value": 70 }, { "color": "red", "value": 90 }] } }, "overrides": [] }
    },
    {
      "id": 5, "title": "Disk", "type": "gauge",
      "gridPos": { "h": 4, "w": 6, "x": 18, "y": 1 },
      "targets": [{ "expr": "system_disk_used_bytes{backend_id=~\"$backend\"} / system_disk_total_bytes{backend_id=~\"$backend\"} * 100", "legendFormat": "{{ backend_id }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100, "thresholds": { "steps": [{ "color": "green", "value": null }, { "color": "yellow", "value": 70 }, { "color": "red", "value": 90 }] } }, "overrides": [] }
    },
    {
      "id": 6, "title": "CPU Load", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 0, "y": 5 },
      "targets": [
        { "expr": "system_cpu_load_1m{backend_id=~\"$backend\"}",  "legendFormat": "{{ backend_id }} 1m",  "refId": "A" },
        { "expr": "system_cpu_load_5m{backend_id=~\"$backend\"}",  "legendFormat": "{{ backend_id }} 5m",  "refId": "B" },
        { "expr": "system_cpu_load_15m{backend_id=~\"$backend\"}", "legendFormat": "{{ backend_id }} 15m", "refId": "C" }
      ],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 10 }, "unit": "short" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 7, "title": "Memory Over Time", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 12, "y": 5 },
      "targets": [
        { "expr": "system_memory_used_bytes{backend_id=~\"$backend\"}",  "legendFormat": "{{ backend_id }} Used",  "refId": "A" },
        { "expr": "system_memory_total_bytes{backend_id=~\"$backend\"}", "legendFormat": "{{ backend_id }} Total", "refId": "B" }
      ],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 10 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 22, "title": "Container Metrics", "type": "row",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 11 },
      "collapsed": false
    },
    {
      "id": 8, "title": "Container CPU (cores)", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 0, "y": 12 },
      "targets": [{ "expr": "rate(container_cpu_usage_seconds{container_name!~\"containarium-core-.*\",backend_id=~\"$backend\"}[5m])", "legendFormat": "{{ container_name }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "short" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 9, "title": "Container Memory", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 12, "y": 12 },
      "targets": [{ "expr": "container_memory_usage_bytes{container_name!~\"containarium-core-.*\",backend_id=~\"$backend\"}", "legendFormat": "{{ container_name }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 10, "title": "Container Disk", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 0, "y": 18 },
      "targets": [{ "expr": "container_disk_usage_bytes{container_name!~\"containarium-core-.*\",backend_id=~\"$backend\"}", "legendFormat": "{{ container_name }}", "refId": "A" }],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 11, "title": "Container Network I/O", "type": "timeseries",
      "gridPos": { "h": 6, "w": 12, "x": 12, "y": 18 },
      "targets": [
        { "expr": "container_network_rx_bytes{container_name!~\"containarium-core-.*\",backend_id=~\"$backend\"}", "legendFormat": "{{ container_name }} RX", "refId": "A" },
        { "expr": "container_network_tx_bytes{container_name!~\"containarium-core-.*\",backend_id=~\"$backend\"}", "legendFormat": "{{ container_name }} TX", "refId": "B" }
      ],
      "datasource": { "type": "prometheus", "uid": "victoriametrics" },
      "fieldConfig": { "defaults": { "custom": { "lineWidth": 1, "fillOpacity": 5 }, "unit": "bytes" }, "overrides": [] },
      "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
    },
    {
      "id": 17, "title": "Alerts", "type": "row",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 22 },
      "collapsed": true,
      "panels": [
        {
          "id": 18, "title": "Firing Alerts", "type": "stat",
          "gridPos": { "h": 4, "w": 4, "x": 0, "y": 23 },
          "targets": [{ "expr": "count(ALERTS{alertstate=\"firing\"}) or vector(0)", "refId": "A", "instant": true }],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": { "thresholds": { "steps": [{ "color": "green", "value": null }, { "color": "orange", "value": 1 }, { "color": "red", "value": 3 }] } }, "overrides": [] }
        },
        {
          "id": 20, "title": "Active Alerts", "type": "table",
          "gridPos": { "h": 6, "w": 20, "x": 4, "y": 23 },
          "targets": [{ "expr": "ALERTS{alertstate=\"firing\"}", "refId": "A", "instant": true, "format": "table" }],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": {}, "overrides": [] },
          "transformations": [
            { "id": "organize", "options": { "excludeByName": { "Time": true, "Value": true, "__name__": true, "alertstate": true, "source": true, "service_name": true }, "renameByName": { "alertname": "Alert", "alertgroup": "Group", "severity": "Severity" } } }
          ],
          "options": { "showHeader": true, "footer": { "show": false } }
        },
        {
          "id": 19, "title": "Alerts Over Time", "type": "timeseries",
          "gridPos": { "h": 6, "w": 24, "x": 0, "y": 29 },
          "targets": [
            { "expr": "count(ALERTS{alertstate=\"firing\"}) or vector(0)", "legendFormat": "Firing", "refId": "A" },
            { "expr": "count(ALERTS{alertstate=\"pending\"}) or vector(0)", "legendFormat": "Pending", "refId": "B" }
          ],
          "datasource": { "type": "prometheus", "uid": "victoriametrics" },
          "fieldConfig": { "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 20 }, "unit": "short" }, "overrides": [{ "matcher": { "id": "byName", "options": "Firing" }, "properties": [{ "id": "color", "value": { "fixedColor": "red", "mode": "fixed" } }] }] },
          "options": { "legend": { "displayMode": "list", "placement": "bottom" } }
        }
      ]
    },
    {
      "id": 12, "title": "Core Infrastructure", "type": "row",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 30 },
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
  "templating": {
    "list": [
      {
        "name": "backend",
        "type": "query",
        "label": "Backend Node",
        "datasource": { "type": "prometheus", "uid": "victoriametrics" },
        "query": "label_values(container_cpu_usage_seconds, backend_id)",
        "includeAll": true,
        "allValue": ".*",
        "current": { "text": "All", "value": "$__all" },
        "refresh": 2,
        "sort": 1,
        "multi": false
      }
    ]
  },
  "annotations": { "list": [] }
}`
