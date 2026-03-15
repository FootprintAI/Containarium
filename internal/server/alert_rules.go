package server

// DefaultAlertRules is the YAML content for vmalert default rules.
// Written to /etc/vmalert/rules/default.yml inside the VictoriaMetrics container.
const DefaultAlertRules = `groups:
  - name: system_alerts
    interval: 30s
    rules:
      - alert: HighMemoryUsage
        expr: system_memory_used_bytes / system_memory_total_bytes * 100 > 90
        for: 5m
        labels:
          severity: critical
          source: default
        annotations:
          summary: "High memory usage detected"
          description: "System memory usage is above 90% for more than 5 minutes (current: {{ $value | printf \"%.1f\" }}%%)."

      - alert: HighDiskUsage
        expr: system_disk_used_bytes / system_disk_total_bytes * 100 > 85
        for: 5m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "High disk usage detected"
          description: "System disk usage is above 85% for more than 5 minutes (current: {{ $value | printf \"%.1f\" }}%%)."

      - alert: DiskAlmostFull
        expr: system_disk_used_bytes / system_disk_total_bytes * 100 > 95
        for: 2m
        labels:
          severity: critical
          source: default
        annotations:
          summary: "Disk almost full"
          description: "System disk usage is above 95% for more than 2 minutes (current: {{ $value | printf \"%.1f\" }}%%). Immediate action required."

      - alert: HighCPULoad
        expr: system_cpu_load_5m > system_cpu_count * 0.8
        for: 5m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "High CPU load detected"
          description: "System 5-minute CPU load average is above 80% of available cores for more than 5 minutes."

      - alert: MetricsCollectionDown
        expr: absent(system_cpu_count)
        for: 5m
        labels:
          severity: critical
          source: default
        annotations:
          summary: "Metrics collection is down"
          description: "No system metrics have been received for more than 5 minutes. The metrics collector may be down."

  - name: container_alerts
    interval: 30s
    rules:
      - alert: ContainerHighMemory
        expr: container_memory_usage_bytes{container_name!~"containarium-core-.*"} > 3.5e9
        for: 5m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Container using high memory"
          description: "Container {{ $labels.container_name }} is using more than 3.5GB of memory for more than 5 minutes."

      - alert: ContainerHighCPU
        expr: rate(container_cpu_usage_seconds{container_name!~"containarium-core-.*"}[5m]) > 0.9
        for: 10m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Container using high CPU"
          description: "Container {{ $labels.container_name }} is using more than 90% of a CPU core for more than 10 minutes."

      - alert: ContainerStopped
        expr: containarium_containers_stopped > 0
        for: 10m
        labels:
          severity: info
          source: default
        annotations:
          summary: "Stopped containers detected"
          description: "There are {{ $value }} stopped containers for more than 10 minutes."

      - alert: NoRunningContainers
        expr: containarium_containers_running == 0
        for: 5m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "No running containers"
          description: "There are no running user containers for more than 5 minutes."

  - name: pentest_alerts
    interval: 60s
    rules:
      - alert: PentestCriticalFindings
        expr: pentest_findings_open{severity="critical"} > 0
        for: 5m
        labels:
          severity: critical
          source: default
        annotations:
          summary: "Critical pentest findings detected"
          description: "There are {{ $value }} critical security findings from automated penetration testing."

      - alert: PentestHighFindings
        expr: pentest_findings_open{severity="high"} > 3
        for: 10m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Multiple high-severity pentest findings"
          description: "There are {{ $value }} high-severity security findings from automated penetration testing."

      - alert: PentestScanStale
        expr: time() - pentest_scan_last_timestamp > 172800
        for: 5m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Pentest scan is stale"
          description: "No penetration test scan has completed in the last 48 hours."

      - alert: PentestHighCPU
        expr: avg_over_time(system_cpu_load_1m[10m]) > system_cpu_count * 0.9
        for: 10m
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Sustained high CPU during pentest"
          description: "System CPU load has been above 90% for 10 minutes, possibly due to an active pentest scan or attack."
`
