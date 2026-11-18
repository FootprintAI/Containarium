# Stage 3b refuses name-only cluster certificates: gate must pass on every daemon

Issue: #3689
Change: #3724

## Gate
Run on every daemon that runs clusters, and again immediately before deploying
the release. It must return no rows:

```sql
SELECT state, count(*) FROM k8s_clusters
WHERE state <> 'deleting' AND (ca_id_bound = false OR ca_deploy_gen < 1)
GROUP BY state;
```

Also confirm on one real control-plane VM that the autoscaler restarted after
its credential was written: `systemctl show k3s-cluster-autoscaler -p
ActiveEnterTimestamp` is later than the modification time of the client
certificate file.

## Evidence to record when clearing
The query's result per daemon (counts), the spot-check result, and who ran
them. No host, cluster or tenant names.
