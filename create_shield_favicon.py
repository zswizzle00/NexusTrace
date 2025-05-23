from PIL import Image, ImageDraw
import os

def get_shield_points(size=32):
    # SVG viewBox is 0 0 24 24, so scale accordingly
    scale = size / 24
    points = [
        (12, 3), (19, 7), (19, 12), (15.5, 21.74), (12, 23), (8.5, 21.74), (5, 12), (5, 7)
    ]
    return [(x * scale, y * scale) for x, y in points]

def create_shield_favicon():
    size = 32
    shield_color = (59, 130, 246, 255)  # Blue
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    points = get_shield_points(size)
    # Draw the outline as a polygon for sharp corners
    draw.polygon(points, outline=shield_color, fill=None, width=3)
    if not os.path.exists('static'):
        os.makedirs('static')
    image.save('static/favicon.ico', format='ICO')

if __name__ == "__main__":
    create_shield_favicon() 