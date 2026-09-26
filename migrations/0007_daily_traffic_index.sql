-- The daily report needs the sample immediately before midnight for each
-- (node, route) counter. Keep those lookups indexed as history grows.
CREATE INDEX idx_traffic_node_route_bucket
ON traffic_stats (node_id, route_id, bucket_at DESC, id DESC);
