import PyInstaller.__main__

if __name__ == "__main__":
    PyInstaller.__main__.run(
        (
            "src\\app.py",
            "--onefile",
            "--icon",
            "logo.ico",
            "--uac-admin",
            "--name",
            "Guardian",
            "--version-file",
            "version.txt",
        )
    )
