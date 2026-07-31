from PIL import Image, ImageDraw
import os

def create_favicon():
    size = 32
    image = Image.new('RGBA', (size, size), (59, 130, 246, 255))  # #3B82F6
    draw = ImageDraw.Draw(image)
    
    draw.line([(8, 16), (14, 22), (24, 10)], fill='white', width=3)
    
    if not os.path.exists('static'):
        os.makedirs('static')
    image.save('static/favicon.ico', format='ICO')

if __name__ == '__main__':
    create_favicon() 