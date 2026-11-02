-- watch_http for hosts that activated before it existed, as in 0003_host_capabilities.sql.
UPDATE "agentHost" SET "defaultCapabilities" = '["create_project","get_project","schedule_http","get_task","list_tasks","cancel_task","redrive_task","create_cron","get_cron","list_crons","delete_cron","watch_http"]' WHERE "userId" IS NULL;
