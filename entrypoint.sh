#!/bin/sh
exec gunicorn --bind 0.0.0.0:${PORT:-591} wsgi:app 