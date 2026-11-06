"""Componentes nativos do LabGuard: cartões e botões desenhados com Tk."""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

BG = "#F5F3FC"
PANEL = "#FFFFFF"
CARD = "#EFEAFF"
TEXT = "#21183F"
MUTED = "#736B87"
PURPLE = "#6C42D9"
BLUE = "#3478F6"
AMBER = "#F4C84A"
GREEN = "#13846B"
RED = "#C24769"
SIDEBAR = "#29184F"
BORDER = "#E5DFF3"


def background(widget):
    try:
        return widget.cget("background")
    except tk.TclError:
        return BG


def rounded(canvas, x1, y1, x2, y2, radius=18, **kwargs):
    radius = min(radius, max(0, (x2 - x1) / 2), max(0, (y2 - y1) / 2))
    points = [x1+radius,y1,x1+radius,y1,x2-radius,y1,x2-radius,y1,
              x2,y1,x2,y1+radius,x2,y1+radius,x2,y2-radius,
              x2,y2-radius,x2,y2,x2-radius,y2,x2-radius,y2,
              x1+radius,y2,x1+radius,y2,x1,y2,x1,y2-radius,
              x1,y2-radius,x1,y1+radius,x1,y1+radius,x1,y1]
    return canvas.create_polygon(points, smooth=True, splinesteps=24, **kwargs)


class ActionButton(tk.Canvas):
    """Botão com foco, teclado, hover e leve profundidade, sem dependências."""
    def __init__(self, parent, text="", command=None, style="TButton", state="normal", **kwargs):
        self._text = text
        self._command = command
        self._style_name = style
        self._state = state
        self._hover = False
        self._pressed = False
        self._focused = False
        font = kwargs.pop("font", None) or tkfont.nametofont("TkDefaultFont").copy()
        if isinstance(font, tkfont.Font):
            font.configure(size=10, weight="bold")
        self._font = font
        self._requested_width = kwargs.pop("width", None)
        self._height = kwargs.pop("height", 44)
        parent_bg = kwargs.pop("bg", kwargs.pop("background", background(parent)))
        kwargs.pop("padding", None)
        self._custom_bg = None
        self._custom_fg = None
        super().__init__(parent, bg=parent_bg, height=self._height, highlightthickness=0,
                         borderwidth=0, takefocus=1, cursor="hand2", **kwargs)
        self._resize()
        self.bind("<Configure>", lambda _: self._paint())
        self.bind("<Enter>", lambda _: self._motion(True))
        self.bind("<Leave>", lambda _: self._motion(False))
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<FocusIn>", lambda _: self._focus(True))
        self.bind("<FocusOut>", lambda _: self._focus(False))
        self.bind("<Return>", self._invoke)
        self.bind("<space>", self._invoke)

    def _resize(self):
        font = self._font if isinstance(self._font, tkfont.Font) else tkfont.Font(font=self._font)
        size = font.measure(self._text) + 36
        if self._requested_width:
            size = max(size, int(self._requested_width) * 8)
        super().configure(width=size)

    def _colors(self):
        if self._state == "disabled":
            return "#ECE8F4", "#A49AB6", "#E1DCEB"
        if "Nav" in self._style_name:
            return ("#49316E" if self._hover else SIDEBAR), "#D5CAE9", SIDEBAR
        if "Accent" in self._style_name:
            return ("#4C8AFF" if self._hover else BLUE), "#FFFFFF", "#2357B6"
        if "Purple" in self._style_name:
            return ("#8159E3" if self._hover else PURPLE), "#FFFFFF", "#4C269F"
        if "Yellow" in self._style_name:
            return ("#FFDA68" if self._hover else AMBER), "#3F2E08", "#D6AA2B"
        if "Danger" in self._style_name:
            return ("#FADDE5" if self._hover else "#FCE9EF"), RED, "#EFC4CF"
        return ("#E8E0FC" if self._hover else "#F0EBFA"), PURPLE, "#DCD2EE"

    def _paint(self):
        self.delete("all")
        width, height = max(self.winfo_width(), 20), max(self.winfo_height(), 20)
        face, color, shadow = self._colors()
        face = self._custom_bg or face
        color = self._custom_fg or color
        offset = 2 if self._pressed else 0
        rounded(self, 1, 4, width-1, height-1, 12, fill=shadow, outline="")
        rounded(self, 1, 1+offset, width-1, height-4+offset, 12,
                fill=face, outline=PURPLE if self._focused else face,
                width=2 if self._focused else 0)
        self.create_text(width/2, (height-3)/2+offset, text=self._text, fill=color, font=self._font)

    def _motion(self, hover):
        self._hover = hover
        if not hover:
            self._pressed = False
        self._paint()

    def _focus(self, focused):
        self._focused = focused
        self._paint()

    def _press(self, _event):
        if self._state != "disabled":
            self.focus_set()
            self._pressed = True
            self._paint()

    def _release(self, event):
        pressed = self._pressed
        self._pressed = False
        self._paint()
        if pressed and 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height():
            self._invoke()

    def _invoke(self, _event=None):
        if self._state != "disabled" and self._command:
            self._command()
        return "break"

    def invoke(self):
        return self._invoke()

    def configure(self, cnf=None, **kwargs):
        if isinstance(cnf, dict):
            kwargs = dict(cnf, **kwargs)
        if "text" in kwargs:
            self._text = str(kwargs.pop("text"))
            self._resize()
        if "state" in kwargs:
            self._state = kwargs.pop("state")
            super().configure(cursor="arrow" if self._state == "disabled" else "hand2")
        if "command" in kwargs:
            self._command = kwargs.pop("command")
        if "style" in kwargs:
            self._style_name = kwargs.pop("style")
        if "fg" in kwargs or "foreground" in kwargs:
            self._custom_fg = kwargs.pop("fg", kwargs.pop("foreground", None))
        if "face" in kwargs:
            self._custom_bg = kwargs.pop("face")
        if kwargs:
            super().configure(**kwargs)
        self._paint()

    config = configure

    def cget(self, key):
        if key == "text":
            return self._text
        if key == "state":
            return self._state
        return super().cget(key)


class RoundCard(tk.Canvas):
    """Cartão responsivo; widgets de conteúdo são colocados em `.body`."""
    def __init__(self, parent, color=PANEL, padding=18, border=BORDER, radius=20, **kwargs):
        self.color, self.padding, self.border, self.radius = color, padding, border, radius
        super().__init__(parent, bg=background(parent), highlightthickness=0,
                         borderwidth=0, height=100, **kwargs)
        self.body = tk.Frame(self, bg=color)
        self._body_id = self.create_window((padding, padding), window=self.body, anchor="nw")
        self.bind("<Configure>", self._layout)
        self.body.bind("<Configure>", self._body_layout)

    def _body_layout(self, _event):
        requested = self.body.winfo_reqheight() + self.padding*2 + 4
        if abs(self.winfo_reqheight() - requested) > 1:
            self.configure(height=requested)
        self._draw()

    def _layout(self, event):
        self.itemconfigure(self._body_id, width=max(40, event.width - self.padding*2))
        self._draw()

    def _draw(self):
        self.delete("surface")
        width, height = self.winfo_width(), self.winfo_height()
        rounded(self, 1, 4, width-1, height-1, self.radius, fill="#EAE4F4", outline="", tags="surface")
        rounded(self, 1, 1, width-1, height-4, self.radius, fill=self.color,
                outline=self.border, width=1, tags="surface")
        self.tag_lower("surface")


class IconBadge(tk.Canvas):
    def __init__(self, parent, kind="shield", color=PURPLE, tint=CARD, size=40):
        super().__init__(parent, width=size, height=size, bg=background(parent),
                         highlightthickness=0, borderwidth=0)
        rounded(self, 0, 0, size, size, 12, fill=tint, outline="")
        c, s = size/2, size/40
        if kind == "shield":
            self.create_polygon(*[v*s for v in [20,9,30,13,28,25,20,32,12,25,10,13]], fill="", outline=color, width=2)
            self.create_line(*[v*s for v in [15,20,19,24,25,17]], fill=color, width=2)
        elif kind == "computer":
            self.create_rectangle(10*s,10*s,30*s,25*s,outline=color,width=2)
            self.create_line(20*s,25*s,20*s,30*s,fill=color,width=2)
            self.create_line(14*s,31*s,26*s,31*s,fill=color,width=2)
        elif kind == "activity":
            self.create_line(*[v*s for v in [8,22,14,22,18,12,23,29,27,19,33,19]],fill=color,width=2)
        elif kind == "network":
            for x,y in [(20,10),(10,28),(30,28)]:
                self.create_oval((x-4)*s,(y-4)*s,(x+4)*s,(y+4)*s,outline=color,width=2)
            self.create_line(18*s,14*s,12*s,24*s,fill=color,width=2)
            self.create_line(22*s,14*s,28*s,24*s,fill=color,width=2)
        else:
            self.create_text(c,c,text="IA" if kind=="ai" else "DNS",font=("Arial",11,"bold"),fill=color)
