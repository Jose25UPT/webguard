import pdfkit
from jinja2 import Environment, FileSystemLoader
import os
import uuid

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

def generate_pdf_from_json(json_data):
    template = env.get_template("report_template.html")
    html_content = template.render(data=json_data)
    
    output_path = f"/app/results/report_{uuid.uuid4().hex}.pdf"
    pdfkit.from_string(html_content, output_path)
    return output_path
