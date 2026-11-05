# Runs inside `odoo shell`. Makes the database unhealthy in version-independent ways.
Users = env["res.users"].with_context(no_reset_password=True)
admin_group = env.ref("base.group_system")
field = "group_ids" if "group_ids" in Users._fields else "groups_id"
internal = env.ref("base.group_user")
for i in range(1, 9):
    login = f"extra.admin{i}@example.com"
    if not Users.search([("login", "=", login)]):
        Users.create({"name": f"Extra Admin {i}", "login": login, "password": "lab-password-" + str(i), field: [(6, 0, [admin_group.id, internal.id])]})
if not env["ir.mail_server"].search([("name", "=", "Lab SMTP")]):
    env["ir.mail_server"].create({"name": "Lab SMTP", "smtp_host": "smtp.example.com", "smtp_port": 25, "smtp_encryption": "none"})
if "mail.mail" in env:
    for i in range(30):
        env["mail.mail"].create({"subject": f"Stuck {i}", "email_to": "x@example.com", "body_html": "<p>x</p>", "state": "exception", "failure_reason": "Connection refused"})
model = env["ir.model"].search([("model", "=", "res.partner")], limit=1)
if not env["ir.cron"].search([("cron_name", "=", "Lab broken cron")]):
    values = {"name": "Lab broken cron", "model_id": model.id, "state": "code", "code": "raise Exception('lab')", "interval_number": 1, "interval_type": "days"}
    env["ir.cron"].create(values)
env.cr.commit()
print("SEEDED", release.version if "release" in globals() else "")
