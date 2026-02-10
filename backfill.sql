INSERT INTO ip_threats (ip, threat_score, threat_categories, looked_up_at)
SELECT DISTINCT ON (src_ip) src_ip, threat_score, threat_categories, timestamp
FROM logs
WHERE threat_score IS NOT NULL AND src_ip IS NOT NULL
ORDER BY src_ip, timestamp DESC
ON CONFLICT (ip) DO NOTHING;
