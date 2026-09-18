"""Entry point for the built Privacy Shield.app (see PrivacyShield.spec).

The app's executable doubles as the root helper: app.py relaunches it with --helper through the
macOS password prompt. From source, run `python app.py` instead.
"""
import sys

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--helper":
        del sys.argv[1]
        import shield_helper  # standard library only, so Qt never loads in the root process
        shield_helper.main()
    else:
        import app
        app.main()
