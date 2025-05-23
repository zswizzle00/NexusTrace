# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('templates', 'templates'), ('.env', '.')],  # Include .env file
    hiddenimports=['flask', 'jinja2', 'werkzeug'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='IP Checker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=True,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

app = BUNDLE(
    exe,
    name='IP Checker.app',
    icon='icon.icns',
    bundle_identifier='com.ipchecker.app',
    info_plist={
        'CFBundleName': 'IP Checker',
        'CFBundleDisplayName': 'IP Checker',
        'CFBundleExecutable': 'IP Checker',
        'CFBundleIdentifier': 'com.ipchecker.app',
        'CFBundleVersion': '1.0',
        'CFBundleShortVersionString': '1.0',
        'CFBundleDevelopmentRegion': 'English',
        'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundlePackageType': 'APPL',
        'LSMinimumSystemVersion': '10.13',
        'NSHighResolutionCapable': True,
        'LSUIElement': True,
    },
) 