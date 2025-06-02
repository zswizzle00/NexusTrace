from dotenv import load_dotenv
import os

# Load environment variables first, before any other imports
load_dotenv()

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050) 