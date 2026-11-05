from odoo import http
from odoo.http import request


class LabController(http.Controller):
    @http.route("/lab/orders", auth="public", type="http", csrf=False)
    def orders(self, **kw):
        return str(request.env["lab.order"].sudo().search([]).ids)
