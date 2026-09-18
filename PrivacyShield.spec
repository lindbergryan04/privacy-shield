# PyInstaller recipe for "Privacy Shield.app". Build it with ./build_app.sh
import os

here = SPECPATH

a = Analysis(
    [os.path.join(here, "launcher.py")],
    pathex=[here],
    datas=[(os.path.join(here, "blocklists"), "blocklists")],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Privacy Shield", console=False)
coll = COLLECT(exe, a.binaries, a.datas, name="Privacy Shield")
app = BUNDLE(
    coll,
    name="Privacy Shield.app",
    icon=os.path.join(here, "assets", "PrivacyShield.icns"),
    bundle_identifier="com.privacyshield.app",
    version="0.2.0",
    info_plist={"NSHighResolutionCapable": True, "LSMinimumSystemVersion": "11.0"},
)
