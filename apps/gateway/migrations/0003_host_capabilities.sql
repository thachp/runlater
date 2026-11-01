-- Agent Auth saves a host's capabilities when it activates and never widens them. Every
-- autonomous host (no user) is meant to hold every capability, so hosts from before the cron
-- tools hold only the original seven. Adding a capability needs a migration like this one;
-- test/host-capabilities.test.ts fails until there is.
UPDATE "agentHost" SET "defaultCapabilities" = '["create_project","get_project","schedule_http","get_task","list_tasks","cancel_task","redrive_task","create_cron","get_cron","list_crons","delete_cron"]' WHERE "userId" IS NULL;
