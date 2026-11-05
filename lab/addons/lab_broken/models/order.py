"""Every function below contains a mistake odoo-doctor must catch."""
import pickle
import subprocess

import requests

from odoo import fields, models

API_KEY = "sk_live_51Habcdefghijklmnopqrstuv"


class LabOrder(models.Model):
    _name = "lab.order"
    _description = "Lab order"

    name = fields.Char()
    amount = fields.Float()
    partner_id = fields.Many2one("res.partner")
    note = fields.Html(sanitize=False)

    def find_by_name(self, name):
        self.env.cr.execute(f"SELECT id FROM lab_order WHERE name = '{name}'")
        return self.env.cr.fetchall()

    def find_percent(self, name):
        self.env.cr.execute("SELECT id FROM lab_order WHERE name = '%s'" % name)

    def safe_query(self, name):
        self.env.cr.execute("SELECT id FROM lab_order WHERE name = %s", (name,))

    def commit_in_loop(self):
        for order in self:
            order.amount = 0
            self.env.cr.commit()

    def n_plus_one(self):
        for order in self:
            order.env["res.partner"].search([("id", "=", order.partner_id.id)])

    def call_partner_api(self):
        return requests.get("https://example.com/api", verify=False)

    def run_shell(self, name):
        return subprocess.run(f"echo {name}", shell=True, check=False)

    def load_blob(self, blob):
        return pickle.loads(blob)

    def run_user_code(self, code):
        return eval(code)
