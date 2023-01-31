import PyInstaller.__main__

version = "3.3.1"

if __name__ == "__main__":
    PyInstaller.__main__.run(
        (
            "src\\app.py",
            "--onefile",
            "--icon",
            "logo.ico",
            "--uac-admin",
            "--name",
            f"Guardian-{version}",
            "--version-file",
            "version.txt",
        )
    )
