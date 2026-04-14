import json
import os
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# Color palette
NAVY = (23, 37, 63)
DARK_GRAY = (51, 51, 51)
MEDIUM_GRAY = (102, 102, 102)
LIGHT_GRAY = (245, 245, 248)
ACCENT = (41, 98, 168)
TABLE_HEADER_BG = (23, 37, 63)
TABLE_HEADER_FG = (255, 255, 255)
TABLE_ALT_ROW = (248, 249, 252)
WHITE = (255, 255, 255)
RULE_COLOR = (200, 205, 215)

MARGIN_LEFT = 25
MARGIN_RIGHT = 25
MARGIN_TOP = 25
MARGIN_BOTTOM = 25


class ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_margins(MARGIN_LEFT, MARGIN_TOP, MARGIN_RIGHT)
        self.set_auto_page_break(auto=True, margin=MARGIN_BOTTOM)
        self.content_w = self.w - MARGIN_LEFT - MARGIN_RIGHT

    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*MEDIUM_GRAY)
            self.set_y(10)
            self.cell(0, 5, "NetSec Toolkit  |  Security Report  |  Fardin Iqbal", align="L",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_draw_color(*RULE_COLOR)
            self.line(MARGIN_LEFT, 17, self.w - MARGIN_RIGHT, 17)
            self.set_y(MARGIN_TOP)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*MEDIUM_GRAY)
        self.cell(0, 10, str(self.page_no()), align="C")

    def add_title_page(self):
        self.ln(40)
        # Thin accent line
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.8)
        self.line(MARGIN_LEFT, self.get_y(), self.w - MARGIN_RIGHT, self.get_y())
        self.ln(10)

        self.set_font("Helvetica", "B", 24)
        self.set_text_color(*NAVY)
        self.cell(0, 12, "Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        self.ln(3)

        self.set_font("Helvetica", "", 13)
        self.set_text_color(*MEDIUM_GRAY)
        self.cell(0, 7, "Network Security", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        self.ln(12)

        self.set_font("Helvetica", "", 10.5)
        self.set_text_color(*DARK_GRAY)
        info_lines = [
            "NetSec Toolkit: Network Security Analysis",
            "2026",
            "",
            "Fardin Iqbal",
        ]
        for line in info_lines:
            if line == "":
                self.ln(4)
            else:
                self.cell(0, 6, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

        self.ln(12)
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.4)
        self.line(MARGIN_LEFT, self.get_y(), MARGIN_LEFT + 40, self.get_y())

    def add_section(self, number, title):
        self.ln(8)
        self.set_draw_color(*RULE_COLOR)
        self.set_line_width(0.3)
        y = self.get_y()
        self.line(MARGIN_LEFT, y, self.w - MARGIN_RIGHT, y)
        self.ln(5)
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(*NAVY)
        self.cell(0, 9, f"{number}   {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

    def add_subsection(self, number, title):
        self.ln(5)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*ACCENT)
        self.cell(0, 7, f"{number}   {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def add_body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*DARK_GRAY)
        self.multi_cell(0, 5.2, text)
        self.ln(3)

    def add_bold_label(self, label):
        self.ln(2)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*DARK_GRAY)
        self.cell(0, 5.5, label, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def add_screenshot(self, image_path, caption=None):
        if caption:
            self.set_font("Helvetica", "I", 8.5)
            self.set_text_color(*MEDIUM_GRAY)
            self.cell(0, 5, caption, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)
        if os.path.exists(image_path):
            from PIL import Image as PILImage
            img = PILImage.open(image_path)
            img_w, img_h = img.size
            available_w = self.content_w
            scale = available_w / (img_w * 0.264583)
            rendered_h = (img_h * 0.264583) * scale
            if rendered_h > 110:
                self.image(image_path, x=MARGIN_LEFT, h=110)
            else:
                self.image(image_path, x=MARGIN_LEFT, w=available_w)
            self.ln(5)

    def add_table(self, headers, rows):
        total_w = self.content_w
        if len(headers) == 4:
            col_widths = [14, 24, 42, total_w - 80]
        else:
            col_widths = [total_w / len(headers)] * len(headers)

        # Header row
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*TABLE_HEADER_BG)
        self.set_text_color(*TABLE_HEADER_FG)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 7, f"  {h}", border=0, fill=True)
        self.ln()

        # Data rows
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*DARK_GRAY)
        for row_idx, row in enumerate(rows):
            if row_idx % 2 == 1:
                self.set_fill_color(*TABLE_ALT_ROW)
            else:
                self.set_fill_color(*WHITE)

            max_lines = 1
            cell_texts = []
            for i, cell in enumerate(row):
                cell_texts.append(str(cell))
                lines_needed = max(1, int(len(str(cell)) * 2.2 / col_widths[i]) + 1)
                max_lines = max(max_lines, lines_needed)

            row_height = 6 * max_lines
            x_start = self.get_x()
            y_start = self.get_y()

            if y_start + row_height > self.h - MARGIN_BOTTOM:
                self.add_page()
                y_start = self.get_y()

            for i, cell in enumerate(cell_texts):
                self.set_xy(x_start + sum(col_widths[:i]), y_start)
                fill = row_idx % 2 == 1
                if fill:
                    self.set_fill_color(*TABLE_ALT_ROW)
                else:
                    self.set_fill_color(*WHITE)
                self.multi_cell(col_widths[i], 6, f"  {cell}", border=0, fill=fill)

            self.set_y(y_start + row_height)

        # Bottom rule
        self.set_draw_color(*RULE_COLOR)
        self.set_line_width(0.3)
        self.line(MARGIN_LEFT, self.get_y(), MARGIN_LEFT + total_w, self.get_y())
        self.ln(5)


def load_file(path):
    with open(path) as f:
        return f.read()


def main():
    pdf = ReportPDF()
    pdf.add_page()

    # Title page
    pdf.add_title_page()
    pdf.add_page()

    # Load all data
    nmap_output = load_file("output/nmap_output.txt")
    traceroute_google = load_file("output/traceroute_google.txt")
    traceroute_scanme = load_file("output/traceroute_scanme.txt")
    scapy_ping = load_file("output/scapy_ping_output.txt")
    scapy_syn = load_file("output/scapy_syn_output.txt")
    answers = json.loads(load_file("output/answers.json"))

    # ---- PART A ----
    pdf.add_section("1", "Part A: Network Reconnaissance and Path Analysis")

    # 1.1 nmap
    pdf.add_subsection("1.1", "Service Discovery with nmap")
    pdf.add_body("The following screenshot shows the full output of the nmap service version scan against the authorized test target.")
    pdf.add_screenshot("output/screenshots/nmap.png", "nmap -sV scanme.nmap.org")

    # Port table
    pdf.add_bold_label("Open Port Analysis")
    headers = ["Port", "Service", "Version", "Risk Note"]
    rows = [
        ["22", "ssh", "OpenSSH 6.6.1p1",
         "Severely outdated version from 2014 with known CVEs for user enumeration and authentication bypass."],
        ["80", "http", "Apache 2.4.7",
         "Outdated version from 2013 running unencrypted HTTP, missing a decade of security patches."],
        ["9929", "nping-echo", "Nping echo",
         "Diagnostic service running without encryption, could leak network probing information."],
        ["31337", "tcpwrapped", "tcpwrapped",
         "Connection accepted then closed immediately, possibly a honeypot or restricted service on a well-known hacker port."],
    ]
    pdf.add_table(headers, rows)

    pdf.add_bold_label("5a. Are any detected service versions outdated?")
    pdf.add_body(answers["a1_q5a"])

    pdf.add_bold_label("5b. Are any services running over unencrypted protocols?")
    pdf.add_body(answers["a1_q5b"])

    pdf.add_bold_label("5c. Which exposed service would you exploit first?")
    pdf.add_body(answers["a1_q5c"])

    # 1.2 traceroute
    pdf.add_subsection("1.2", "Path Analysis with traceroute")
    pdf.add_body("The following screenshots show the traceroute output for each destination.")
    pdf.add_screenshot("output/screenshots/traceroute_google.png", "traceroute google.com")
    pdf.add_screenshot("output/screenshots/traceroute_scanme.png", "traceroute scanme.nmap.org")

    pdf.add_bold_label("3a. How many hops to reach each destination?")
    pdf.add_body(answers["a2_q3a"])

    pdf.add_bold_label("3b. Why do some hops show * * *?")
    pdf.add_body(answers["a2_q3b"])

    pdf.add_bold_label("3c. Do the two traces share early hops?")
    pdf.add_body(answers["a2_q3c"])

    pdf.add_bold_label("3d. Any hops with significantly higher round-trip times?")
    pdf.add_body(answers["a2_q3d"])

    # 1.3 Scapy
    pdf.add_subsection("1.3", "Packet Crafting with Scapy")

    pdf.add_bold_label("Task A3a: ICMP Ping and TTL Exploration")
    pdf.add_screenshot("output/screenshots/scapy_ping.png", "sudo python3 scapy_ping.py")
    pdf.add_body(answers["a3a_observation"])

    pdf.add_bold_label("Task A3b: TCP SYN Probe")
    pdf.add_screenshot("output/screenshots/scapy_syn.png", "sudo python3 scapy_syn.py")
    pdf.add_body(answers["a3b_observation"])

    # ---- PART B ----
    pdf.add_section("2", "Part B: TLS Handshake Analyzer")

    pdf.add_body(
        "The tls_analyzer.py script connects to each endpoint in targets.txt over TLS, "
        "extracts certificate and session information, runs detection rules for common "
        "misconfigurations, and outputs a structured JSON report. The full output is "
        "included in the submitted tls_report.json file. Below is a summary of findings."
    )

    tls_results = json.loads(load_file("tls_report.json"))
    for result in tls_results:
        target = result["target"]
        if "error" in result:
            pdf.add_bold_label(target)
            pdf.add_body(
                f"Connection failed with error: {result['error']}. "
                "This endpoint requires TLS 1.0, which is blocked at the OpenSSL library level on this system (macOS with OpenSSL 3.x). "
                "Modern OpenSSL builds disable TLS 1.0 and 1.1 by default as a security measure because these protocol versions "
                "have known vulnerabilities including BEAST and POODLE. Even after setting the minimum TLS version to TLSv1 in the "
                "SSLContext, the underlying library refuses to negotiate the connection, resulting in the handshake failure shown above."
            )
        else:
            pdf.add_bold_label(target)
            issues = result.get("issues", [])
            issue_str = ", ".join(issues) if issues else "None"
            leaf = result["leaf_certificate"]
            summary = (
                f"TLS version: {result['tls_version']}. "
                f"Cipher: {result['cipher_suite']}. "
                f"Subject CN: {leaf['subject_cn']}. "
                f"Valid from {leaf['not_before'][:10]} to {leaf['not_after'][:10]}. "
                f"Expired: {leaf['is_expired']}. "
                f"Hostname match: {leaf['hostname_match']}. "
                f"Issues: {issue_str}."
            )
            pdf.add_body(summary)

    # ---- PART C ----
    pdf.add_section("3", "Part C: Short-Answer Questions")

    pdf.add_bold_label("1. Spoofed source IP and port scanning")
    pdf.add_body(answers["c1"])

    pdf.add_bold_label("2. TLS issue and the CIA triad")
    pdf.add_body(answers["c2"])

    # Save
    pdf.output("netsec_report.pdf")
    print("PDF generated: netsec_report.pdf")


if __name__ == "__main__":
    main()
