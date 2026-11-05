-- Version-independent damage that cannot be expressed through the ORM.
DELETE FROM ir_config_parameter WHERE key IN ('auth_signup.invitation_scope', 'web.base.url');
INSERT INTO ir_config_parameter (key, value, create_date, write_date) VALUES
  ('auth_signup.invitation_scope', 'b2c', now(), now()),
  ('web.base.url', 'http://insecure.example.com', now(), now());
UPDATE ir_cron SET nextcall = now() - interval '30 days', lastcall = now() - interval '31 days' WHERE cron_name = 'Lab broken cron';
INSERT INTO lab_order (name, amount, partner_id, create_date, write_date)
SELECT 'order ' || g, g, (SELECT min(id) FROM res_partner), now(), now() FROM generate_series(1, 200000) g
WHERE NOT EXISTS (SELECT 1 FROM lab_order LIMIT 1);
UPDATE lab_order SET amount = amount + 1 WHERE id % 2 = 0;
ANALYZE lab_order;
SELECT count(*) FROM lab_order WHERE partner_id = 1;
SELECT count(*) FROM lab_order WHERE partner_id = 1;
SELECT count(*) FROM lab_order WHERE partner_id = 1;
