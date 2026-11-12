"""Layout library that applies the department's M.Tech/B.Tech report format.

Rules implemented (0.formatting guidelines.docx): Times New Roman, body 12 pt,
justified, 1.5 line spacing, 0.5 cm first-line indent, A4, margins left 1.5 in,
right/top/bottom 1 in. Chapter titles 14 pt bold centred; section headings
12 pt bold left; sub-sections 12 pt italic left. Table captions sit above the
table in bold, figure captions below in regular type, numbered chapter-wise.
Citations are IEEE style [n] numbered in order of first appearance.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Inches, Pt, RGBColor

FONT = "Times New Roman"
TEXT_WIDTH_IN = 8.27 - 1.5 - 1.0
ROMAN = ["", "I", "II", "III", "IV", "V", "VI", "VII", "VIII"]
RED = RGBColor(0xC0, 0x00, 0x00)


def roman_lower(n: int) -> str:
    out, table = "", [(10, "x"), (9, "ix"), (5, "v"), (4, "iv"), (1, "i")]
    for value, symbol in table:
        while n >= value:
            out += symbol
            n -= value
    return out


def set_font(run, size=None, bold=None, italic=None, name=FONT, color=None):
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        fonts.set(qn(attr), name)
    if size:
        run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if italic is not None:
        run.font.italic = italic
    if color is not None:
        run.font.color.rgb = color


def style_font(style, size, bold=False, italic=False):
    style.font.name = FONT
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.italic = italic
    style.font.color.rgb = RGBColor(0, 0, 0)
    rpr = style.element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        fonts.set(qn(attr), FONT)
    for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        if fonts.get(qn(attr)) is not None:
            del fonts.attrib[qn(attr)]


def shade(cell, fill):
    tcpr = cell._element.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcpr.append(shd)


def set_cell_borders(table, size=4, color="000000", none=False):
    tbl = table._element
    props = tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        element = OxmlElement(f"w:{edge}")
        element.set(qn("w:val"), "nil" if none else "single")
        if not none:
            element.set(qn("w:sz"), str(size))
            element.set(qn("w:space"), "0")
            element.set(qn("w:color"), color)
        borders.append(element)
    props.append(borders)


def keep_rows_together(table, header_rows=1):
    for index, row in enumerate(table.rows):
        trpr = row._tr.get_or_add_trPr()
        cant = OxmlElement("w:cantSplit")
        trpr.append(cant)
        if index < header_rows:
            head = OxmlElement("w:tblHeader")
            trpr.append(head)


def add_field(paragraph, instruction, size=12):
    run = paragraph.add_run()
    set_font(run, size)
    for kind, text in (("begin", None), (None, instruction), ("separate", None), (None, "1"), ("end", None)):
        if kind:
            element = OxmlElement("w:fldChar")
            element.set(qn("w:fldCharType"), kind)
        elif text == instruction:
            element = OxmlElement("w:instrText")
            element.set(qn("xml:space"), "preserve")
            element.text = f" {instruction} "
        else:
            element = OxmlElement("w:t")
            element.text = text
        run._element.append(element)


class Doc:
    def __init__(self):
        self.d = Document()
        self._setup_styles()
        self._setup_page(self.d.sections[0])
        self.fig_no: dict[str, str] = {}
        self.tab_no: dict[str, str] = {}
        self.eq_no: dict[str, str] = {}
        self.cite_order: list[str] = []
        self.refs: dict = {}

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup_page(self, section):
        section.page_width, section.page_height = Cm(21.0), Cm(29.7)
        section.left_margin = Inches(1.5)
        section.right_margin = Inches(1.0)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.header_distance = Inches(0.5)
        section.footer_distance = Inches(0.5)

    def _setup_styles(self):
        styles = self.d.styles
        normal = styles["Normal"]
        style_font(normal, 12)
        pf = normal.paragraph_format
        pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        pf.line_spacing = 1.5
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        pf.widow_control = True
        for name, size, bold, italic, align, before, after in (
            ("Heading 1", 14, True, False, WD_ALIGN_PARAGRAPH.CENTER, 0, 14),
            ("Heading 2", 12, True, False, WD_ALIGN_PARAGRAPH.LEFT, 12, 4),
            ("Heading 3", 12, False, True, WD_ALIGN_PARAGRAPH.LEFT, 8, 3),
        ):
            style = styles[name]
            style_font(style, size, bold, italic)
            style.paragraph_format.alignment = align
            style.paragraph_format.space_before = Pt(before)
            style.paragraph_format.space_after = Pt(after)
            style.paragraph_format.line_spacing = 1.5
            style.paragraph_format.keep_with_next = True
        styles["Heading 1"].paragraph_format.page_break_before = True
        from docx.enum.style import WD_STYLE_TYPE
        for name, align, bold in (("TableCaption", WD_ALIGN_PARAGRAPH.CENTER, True),
                                  ("FigCaption", WD_ALIGN_PARAGRAPH.CENTER, False)):
            style = styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
            style.base_style = styles["Normal"]
            style_font(style, 12, bold)
            style.paragraph_format.alignment = align
            style.paragraph_format.line_spacing = 1.0
            style.paragraph_format.space_before = Pt(6)
            style.paragraph_format.space_after = Pt(6)
        styles["TableCaption"].paragraph_format.keep_with_next = True

    # ------------------------------------------------------------------
    # Inline text
    # ------------------------------------------------------------------

    _TOKEN = re.compile(r"(\*\*.+?\*\*|(?<!_)__(?!_).+?(?<!_)__(?!_)|`.+?`|\{(?:fig|tab|eq|c|sec):[^}]+\})")

    def rich(self, paragraph, text, size=12, bold=False, italic=False, color=None):
        for part in self._TOKEN.split(text):
            if not part:
                continue
            if part.startswith("**"):
                run = paragraph.add_run(part[2:-2])
                set_font(run, size, True, italic, color=color)
            elif part.startswith("__"):
                run = paragraph.add_run(part[2:-2])
                set_font(run, size, bold, True, color=color)
            elif part.startswith("`"):
                run = paragraph.add_run(part[1:-1])
                set_font(run, size - 1.5, bold, italic, name="Courier New", color=color)
            elif re.match(r"{(fig|tab|eq|c|sec):", part):
                kind, key = part[1:-1].split(":", 1)
                run = paragraph.add_run(self.resolve(kind, key))
                set_font(run, size, bold, italic, color=color)
            else:
                run = paragraph.add_run(part)
                set_font(run, size, bold, italic, color=color)

    def resolve(self, kind, key):
        if kind == "fig":
            return f"Figure {self.fig_no[key]}"
        if kind == "tab":
            return f"Table {self.tab_no[key]}"
        if kind == "eq":
            return f"Equation ({self.eq_no[key]})"
        if kind == "sec":
            return f"Section {self.sec_no[key]}"
        keys = [k.strip() for k in key.split(",")]
        return ", ".join(f"[{self.cite_order.index(k) + 1}]" for k in keys)

    # ------------------------------------------------------------------
    # Paragraph-level blocks
    # ------------------------------------------------------------------

    def p(self, text, indent=True, align=None, size=12, keep_next=False, bold=False, italic=False):
        para = self.d.add_paragraph()
        if indent:
            para.paragraph_format.first_line_indent = Cm(0.5)
        if align is not None:
            para.alignment = align
        para.paragraph_format.keep_with_next = keep_next
        self.rich(para, text, size, bold, italic)
        return para

    def heading(self, level, text):
        para = self.d.add_paragraph(style=f"Heading {level}")
        run = para.add_run(text)
        set_font(run, 14 if level == 1 else 12, level < 3, level == 3)
        return para

    def bullets(self, items):
        for text in items:
            para = self.d.add_paragraph()
            para.paragraph_format.left_indent = Cm(1.1)
            para.paragraph_format.first_line_indent = Cm(-0.55)
            para.paragraph_format.space_after = Pt(2)
            run = para.add_run("•\t")
            set_font(run, 12)
            self._tab_stop(para, 1.1)
            self.rich(para, text)

    def numbered(self, items, start=1):
        for i, text in enumerate(items, start):
            para = self.d.add_paragraph()
            para.paragraph_format.left_indent = Cm(1.1)
            para.paragraph_format.first_line_indent = Cm(-0.75)
            para.paragraph_format.space_after = Pt(2)
            run = para.add_run(f"{i}.\t")
            set_font(run, 12)
            self._tab_stop(para, 1.1)
            self.rich(para, text)

    @staticmethod
    def _tab_stop(para, cm):
        para.paragraph_format.tab_stops.add_tab_stop(Cm(cm))

    def code(self, text, size=9):
        for line in text.strip("\n").split("\n"):
            para = self.d.add_paragraph()
            para.alignment = WD_ALIGN_PARAGRAPH.LEFT
            pf = para.paragraph_format
            pf.line_spacing = 1.0
            pf.left_indent = Cm(0.4)
            pf.first_line_indent = Cm(0)
            pf.keep_together = True
            ppr = para._p.get_or_add_pPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), "F2F2F2")
            ppr.append(shd)
            run = para.add_run(line if line else " ")
            set_font(run, size, name="Courier New")
        self.d.add_paragraph().paragraph_format.space_after = Pt(2)

    # ------------------------------------------------------------------
    # Tables, figures, equations
    # ------------------------------------------------------------------

    def table(self, key, caption, header, rows, widths, size=10, align=None, bold_first_col=False):
        number = self.tab_no[key]
        cap = self.d.add_paragraph(style="TableCaption")
        self.rich(cap, f"Table {number}: {caption}", 12, True)
        table = self.d.add_table(rows=1 + len(rows), cols=len(header))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        set_cell_borders(table)
        total = sum(widths)
        scale = TEXT_WIDTH_IN / total if total > TEXT_WIDTH_IN else 1.0
        for r, values in enumerate([header] + rows):
            for c, value in enumerate(values):
                cell = table.cell(r, c)
                cell.width = Inches(widths[c] * scale)
                para = cell.paragraphs[0]
                para.paragraph_format.line_spacing = 1.0
                para.paragraph_format.space_before = Pt(2)
                para.paragraph_format.space_after = Pt(2)
                alignment = (align or ["l"] * len(header))[c]
                para.alignment = {"l": WD_ALIGN_PARAGRAPH.LEFT, "c": WD_ALIGN_PARAGRAPH.CENTER,
                                  "r": WD_ALIGN_PARAGRAPH.RIGHT}[alignment]
                self.rich(para, str(value), size, bold=(r == 0 or (bold_first_col and c == 0)))
                if r == 0:
                    shade(cell, "E7E6E1")
        keep_rows_together(table)
        if len(rows) <= 14:
            for row in table.rows[:-1]:
                for cell in row.cells:
                    for para in cell.paragraphs:
                        para.paragraph_format.keep_with_next = True
        spacer = self.d.add_paragraph()
        spacer.paragraph_format.line_spacing = 1.0
        spacer.paragraph_format.space_after = Pt(4)
        return table

    def figure(self, key, path, caption, width_in):
        para = self.d.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        para.paragraph_format.keep_with_next = True
        para.paragraph_format.line_spacing = 1.0
        para.paragraph_format.space_before = Pt(6)
        para.add_run().add_picture(str(path), width=Inches(min(width_in, TEXT_WIDTH_IN)))
        cap = self.d.add_paragraph(style="FigCaption")
        self.rich(cap, f"Figure {self.fig_no[key]}: {caption}", 12)

    def equation(self, key, text):
        number = self.eq_no[key]
        table = self.d.add_table(rows=1, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        set_cell_borders(table, none=True)
        left, right = table.cell(0, 0), table.cell(0, 1)
        left.width, right.width = Inches(TEXT_WIDTH_IN - 0.8), Inches(0.8)
        lp, rp = left.paragraphs[0], right.paragraphs[0]
        lp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for para in (lp, rp):
            para.paragraph_format.line_spacing = 1.2
            para.paragraph_format.space_before = Pt(4)
            para.paragraph_format.space_after = Pt(4)
        self.rich(lp, text, 12, italic=False)
        self.rich(rp, f"({number})", 12)
        spacer = self.d.add_paragraph()
        spacer.paragraph_format.line_spacing = 1.0
        spacer.paragraph_format.space_after = Pt(2)

    def page_break(self):
        self.d.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ------------------------------------------------------------------
    # Sections and footers
    # ------------------------------------------------------------------

    def new_section(self, number_format=None, start=None, show_number=True):
        section = self.d.add_section(WD_SECTION.NEW_PAGE)
        self._setup_page(section)
        sect = section._sectPr
        for old in sect.findall(qn("w:pgNumType")):
            sect.remove(old)
        if number_format or start:
            pg = OxmlElement("w:pgNumType")
            if number_format:
                pg.set(qn("w:fmt"), number_format)
            if start:
                pg.set(qn("w:start"), str(start))
            sect.append(pg)
        footer = section.footer
        footer.is_linked_to_previous = False
        for para in list(footer.paragraphs):
            for run in list(para.runs):
                run._element.getparent().remove(run._element)
        para = footer.paragraphs[0]
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        if show_number:
            add_field(para, "PAGE")
        return section

    def borderless_table(self, rows, widths, size=12, align=None, bold_header=True, line_spacing=1.15,
                         header=True, row_pad=2):
        table = self.d.add_table(rows=len(rows), cols=len(rows[0]))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        set_cell_borders(table, none=True)
        for r, values in enumerate(rows):
            for c, value in enumerate(values):
                cell = table.cell(r, c)
                cell.width = Inches(widths[c])
                para = cell.paragraphs[0]
                para.paragraph_format.line_spacing = line_spacing
                para.paragraph_format.space_before = Pt(row_pad)
                para.paragraph_format.space_after = Pt(row_pad)
                alignment = (align or ["l"] * len(values))[c]
                para.alignment = {"l": WD_ALIGN_PARAGRAPH.LEFT, "c": WD_ALIGN_PARAGRAPH.CENTER,
                                  "r": WD_ALIGN_PARAGRAPH.RIGHT}[alignment]
                self.rich(para, str(value), size, bold=(header and r == 0 and bold_header))
        return table

    def save(self, path):
        self.d.save(str(path))
