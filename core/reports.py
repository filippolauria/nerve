import csv
import jinja2
import os
import xml.etree.ElementTree as xml

from core.utils import Utils
from itertools import starmap
from version import VERSION


utils = Utils()

allowed_report_types = ['csv', 'html', 'xml', 'txt']


def report_file(report_type):
    report_type = report_type.lower().strip()
    if report_type not in allowed_report_types:
        report_type = allowed_report_types[0]

    uuid = utils.generate_uuid()
    date = utils.get_date()

    filename = f"report-{uuid}-{date}.{report_type}"
    filepath = os.path.join('reports', filename)
    return (filename, filepath)


def map_csv_row(index, i):
    return [
        index,
        i['ip'],
        i['port'],
        i['rule_id'],
        utils.sev_to_human(i['rule_sev']),
        i['rule_desc'],
        i['rule_confirm'],
        i['rule_mitigation']
    ]


def generate_csv(data):
    fieldnames = ['#', 'ip', 'port', 'rule_id', 'rule_severity', 'rule_description', 'rule_confirm', 'rule_mitigation']
    filename, filepath = report_file('csv')

    with open(filepath, mode='w') as fd:
        writer = csv.writer(fd)
        writer.writerow(fieldnames)
        data_values = enumerate(data.values(), 1)
        rows = starmap(map_csv_row, data_values)
        writer.writerows(rows)

    return filename


def write_data(filepath, data):
    with open(filepath, "w") as fd:
        fd.write(data)


def generate_html(vulns, conf):
    # Load the template only once
    templateLoader = jinja2.FileSystemLoader(searchpath="./templates/")
    templateEnv = jinja2.Environment(loader=templateLoader)
    TEMPLATE_FILE = "report_template.html"
    template = templateEnv.get_template(TEMPLATE_FILE)

    # Initialize the vulnerability count
    vuln_count = {i: 0 for i in range(5)}

    # Count and sort vulnerabilities in a single pass
    sorted_vulns = {}
    for k, v in sorted(vulns.items(), key=lambda item: item[1]['rule_sev'], reverse=True):
        vuln_count[v['rule_sev']] += 1
        sorted_vulns[k] = v

    # Prepare the body for the template
    body = {
        'conf': conf,
        'vulns': sorted_vulns,
        'vuln_count': vuln_count,
        'version': VERSION,
    }

    # Render the template with the data
    html = template.render(json_data=body)

    # Write the rendered HTML to the file
    filename, filepath = report_file('html')
    write_data(filepath, html)
    return filename


def generate_txt(vulns):
    # Use a list to accumulate the text parts
    lines = []

    for value in vulns.values():
        for k, v in value.items():
            lines.append(f'{k}:{v}\n')
        lines.append('\n')

    # Join all parts into a single string
    data = ''.join(lines)

    # Get the file path for the report
    filename, filepath = report_file('txt')

    # Write the accumulated data to the file
    write_data(filepath, data)
    return filename


def generate_xml(vulns):
    # Create the root element
    root = xml.Element("Vulnerabilities")

    # Create a list to collect elements
    elements = []

    # Iterate through the vulnerabilities
    for key, value in vulns.items():
        # Create the main vulnerability element
        vuln_element = xml.Element(key)
        elements.append(vuln_element)

        # Create and append sub-elements
        ip = xml.SubElement(vuln_element, "ip")
        ip.text = value['ip']

        port = xml.SubElement(vuln_element, "port")
        port.text = str(value['port'])

        domain = xml.SubElement(vuln_element, "domain")
        domain.text = value['domain']

        sev = xml.SubElement(vuln_element, "severity")
        sev.text = utils.sev_to_human(value['rule_sev'])

        description = xml.SubElement(vuln_element, "description")
        description.text = value['rule_desc']

        confirm = xml.SubElement(vuln_element, "confirm")
        confirm.text = value['rule_confirm']

        details = xml.SubElement(vuln_element, "details")
        details.text = value['rule_details']

        mitigation = xml.SubElement(vuln_element, "mitigation")
        mitigation.text = value['rule_mitigation']

    # Append all collected elements to the root
    for elem in elements:
        root.append(elem)

    # Convert the XML tree to a string
    data = xml.tostring(root)

    # Get the file path for the report
    filename, filepath = report_file('xml')

    # Write the XML string to the file
    write_data(filepath, data.decode('utf-8'))
    return filename
