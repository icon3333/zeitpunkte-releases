"""Regenerate the illustrated README banner (not a device screenshot).

uv run --with fonttools --with cairosvg docs/assets/generate_overview.py
Text is outlined in the SVG; exported assets have no runtime font dependency.
"""
from pathlib import Path
from html import escape

import cairosvg
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen

OUT = Path(__file__).resolve().parent
FONT = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
font = TTFont(FONT)
glyphs = font.getGlyphSet()
cmap = font.getBestCmap()
units = font['head'].unitsPerEm
parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="860" viewBox="0 0 1600 860" role="img" aria-labelledby="title desc">',
         '<title id="title">Zeitpunkte — Zeit auf einen Blick</title>',
         '<desc id="desc">Illustrierte Vorschau der Jahresansicht. Das Punktraster zeigt, wie viel vom Jahr vergangen ist.</desc>',
         '<rect width="1600" height="860" rx="32" fill="#0b0d10"/>']


def text(value, x, y, size, color='#f3f4f6'):
    pen_x = 0
    paths = []
    for char in value:
        name = cmap[ord(char)]
        pen = SVGPathPen(glyphs)
        glyphs[name].draw(pen)
        paths.append(f'<path transform="translate({pen_x} 0)" d="{pen.getCommands()}"/>')
        pen_x += glyphs[name].width
    scale = size / units
    parts.append(f'<g aria-label="{escape(value, quote=True)}" fill="{color}" transform="translate({x} {y}) scale({scale} {-scale})">{"".join(paths)}</g>')


def circle(x, y, r, fill, stroke=None):
    border = f' stroke="{stroke}" stroke-width="2.2"' if stroke else ''
    parts.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}"{border}/>')


for row in range(3):
    for col in range(3):
        circle(94 + col * 18, 99 + row * 18, 4.4, '#64b5f6' if row == 2 and col == 2 else '#f3f4f6')
text('ZEITPUNKTE', 166, 124, 24, '#c0c6d0')
text('Zeit auf', 84, 292, 92)
text('einen Blick.', 84, 394, 92)
text('Ein Punktraster für das, was vergangen ist.', 90, 489, 31, '#b1b8c1')
text('Und für das, was noch bleibt.', 90, 536, 31, '#b1b8c1')
text('TAG  /  MONAT  /  JAHR  /  LEBEN', 92, 635, 26, '#64b5f6')
text('Android-App mit Startbildschirm-Widget', 92, 692, 24, '#c0c6d0')
text('OFFLINE · OHNE KONTO', 92, 777, 21, '#9da6b3')

# An editorial illustration of the existing year view, not rendered app UI.
parts.append('<rect x="1010" y="66" width="440" height="710" rx="48" fill="#000000" stroke="#343941" stroke-width="2"/>')
parts.append('<rect x="1172" y="83" width="116" height="5" rx="2.5" fill="#343941"/>')
text('Jahr', 1048, 146, 25)
text('121 Tage verbleibend', 1048, 189, 24, '#b1b8c1')
for index in range(365):
    row, col = divmod(index, 19)
    x, y = 1054 + col * 19.5, 247 + row * 20
    circle(x, y, 5.4, '#f3f4f6' if index < 244 else '#000000' if index == 244 else '#53565b', '#64b5f6' if index == 244 else None)
text('Einstellungen', 1160, 731, 18, '#64b5f6')
text('ILLUSTRIERTE VORSCHAU', 1083, 817, 22, '#b1b8c1')
parts.append('</svg>')
svg = '\n'.join(parts)
(OUT / 'overview.svg').write_text(svg)
cairosvg.svg2png(bytestring=svg.encode(), write_to=str(OUT / 'overview.png'))
print('Generated', OUT / 'overview.svg', 'and', OUT / 'overview.png')
