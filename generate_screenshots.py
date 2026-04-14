"""Generate terminal-style screenshot images from command output files."""
from PIL import Image, ImageDraw, ImageFont
import os

BG_COLOR = (40, 44, 52)
TEXT_COLOR = (171, 178, 191)
TITLE_COLOR = (130, 170, 255)
PADDING = 20
LINE_HEIGHT = 18
FONT_SIZE = 14

def get_font():
    # Try common monospace fonts
    for name in [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/Library/Fonts/Courier New.ttf",
        "/System/Library/Fonts/Courier.dfont",
    ]:
        if os.path.exists(name):
            try:
                return ImageFont.truetype(name, FONT_SIZE)
            except Exception:
                continue
    return ImageFont.load_default()


def render_terminal(title, text, output_path):
    font = get_font()
    lines = text.strip().split("\n")

    # Add title bar line
    all_lines = [f"$ {title}"] + lines

    # Calculate image size
    max_width = 0
    for line in all_lines:
        bbox = font.getbbox(line)
        w = bbox[2] - bbox[0]
        if w > max_width:
            max_width = w

    # Enforce minimum width of 800px so short outputs don't get stretched in PDF
    img_width = max(800, max_width + PADDING * 2 + 20)
    img_height = len(all_lines) * LINE_HEIGHT + PADDING * 2 + 10

    img = Image.new("RGB", (img_width, img_height), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Draw title bar dots
    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([PADDING + i * 20, 8, PADDING + i * 20 + 12, 20], fill=color)

    y = PADDING + 15
    for i, line in enumerate(all_lines):
        color = TITLE_COLOR if i == 0 else TEXT_COLOR
        draw.text((PADDING, y), line, fill=color, font=font)
        y += LINE_HEIGHT

    img.save(output_path)
    print(f"Saved: {output_path}")


def main():
    os.makedirs("output/screenshots", exist_ok=True)

    with open("output/nmap_output.txt") as f:
        nmap = f.read()
    render_terminal("nmap -sV scanme.nmap.org", nmap, "output/screenshots/nmap.png")

    with open("output/traceroute_google.txt") as f:
        tg = f.read()
    render_terminal("traceroute google.com", tg, "output/screenshots/traceroute_google.png")

    with open("output/traceroute_scanme.txt") as f:
        ts = f.read()
    render_terminal("traceroute scanme.nmap.org", ts, "output/screenshots/traceroute_scanme.png")

    with open("output/scapy_ping_output.txt") as f:
        sp = f.read()
    render_terminal("sudo python3 scapy_ping.py", sp, "output/screenshots/scapy_ping.png")

    with open("output/scapy_syn_output.txt") as f:
        ss = f.read()
    render_terminal("sudo python3 scapy_syn.py", ss, "output/screenshots/scapy_syn.png")


if __name__ == "__main__":
    main()
