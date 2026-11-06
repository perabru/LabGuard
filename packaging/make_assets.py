"""Gera ícone e imagens do instalador na identidade original do LabGuard."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUT = Path(__file__).resolve().parent / "generated"
PURPLE = "#7138E9"
BLUE = "#278BFA"
YELLOW = "#FFD34E"


def font(size, bold=False):
    names = [r"C:\Windows\Fonts\seguisb.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            pass
    return ImageFont.load_default(size=size)


def shield(image, box):
    draw = ImageDraw.Draw(image)
    x, y, size = box
    draw.rounded_rectangle((x, y, x + size, y + size), radius=size * .24, fill=PURPLE)
    points = [(x + size*.5, y + size*.16), (x + size*.79, y + size*.27),
              (x + size*.76, y + size*.62), (x + size*.65, y + size*.76),
              (x + size*.5, y + size*.86), (x + size*.35, y + size*.76),
              (x + size*.24, y + size*.62), (x + size*.21, y + size*.27)]
    draw.polygon(points, fill=BLUE)
    draw.line([(x+size*.35, y+size*.51), (x+size*.46, y+size*.63),
               (x+size*.67, y+size*.38)], fill=YELLOW, width=max(2, int(size*.075)), joint="curve")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    icon = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
    shield(icon, (12, 12, 488))
    icon.save(OUT / "LabGuard.png")
    icon.save(OUT / "LabGuard.ico", sizes=[(16,16), (20,20), (24,24), (32,32), (40,40), (48,48), (64,64), (128,128), (256,256)])
    # Inno Setup scales these high-resolution 2x wizard images.
    wizard = Image.new("RGB", (328, 628), PURPLE)
    draw = ImageDraw.Draw(wizard)
    draw.ellipse((170, -100, 450, 190), fill="#8F5BF0")
    draw.ellipse((-150, 425, 180, 755), fill=BLUE)
    draw.ellipse((250, 480, 420, 650), fill=YELLOW)
    shield(wizard, (46, 58, 116))
    draw.text((40, 220), "LabGuard", font=font(38, True), fill="white")
    draw.text((41, 277), "Mais foco na aula.", font=font(20), fill="white")
    draw.text((41, 309), "Mais controle", font=font(20), fill="white")
    draw.text((41, 341), "no laboratório.", font=font(20), fill="white")
    wizard.save(OUT / "wizard.bmp")
    small = Image.new("RGB", (110, 110), "white")
    shield(small, (9, 9, 92))
    small.save(OUT / "wizard-small.bmp")
    print(OUT)


if __name__ == "__main__":
    main()
