from PIL import Image, ImageDraw, ImageFont
import os

# Create a 1024x1024 image with a blue background
img = Image.new('RGBA', (1024, 1024), (41, 128, 185, 255))
draw = ImageDraw.Draw(img)

# Try to load a font, fall back to default if not available
try:
    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 200)
except:
    font = ImageFont.load_default()

# Draw "IP" text in white
text = "IP"
text_bbox = draw.textbbox((0, 0), text, font=font)
text_width = text_bbox[2] - text_bbox[0]
text_height = text_bbox[3] - text_bbox[1]
x = (1024 - text_width) // 2
y = (1024 - text_height) // 2
draw.text((x, y), text, font=font, fill=(255, 255, 255, 255))

# Save the image
img.save('icon.png')

# Convert to .icns using iconutil
os.system('mkdir icon.iconset')
os.system('sips -z 16 16 icon.png --out icon.iconset/icon_16x16.png')
os.system('sips -z 32 32 icon.png --out icon.iconset/icon_16x16@2x.png')
os.system('sips -z 32 32 icon.png --out icon.iconset/icon_32x32.png')
os.system('sips -z 64 64 icon.png --out icon.iconset/icon_32x32@2x.png')
os.system('sips -z 128 128 icon.png --out icon.iconset/icon_128x128.png')
os.system('sips -z 256 256 icon.png --out icon.iconset/icon_128x128@2x.png')
os.system('sips -z 256 256 icon.png --out icon.iconset/icon_256x256.png')
os.system('sips -z 512 512 icon.png --out icon.iconset/icon_256x256@2x.png')
os.system('sips -z 512 512 icon.png --out icon.iconset/icon_512x512.png')
os.system('sips -z 1024 1024 icon.png --out icon.iconset/icon_512x512@2x.png')
os.system('iconutil -c icns icon.iconset')
os.system('rm -rf icon.iconset icon.png') 