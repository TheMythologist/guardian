import PyInstaller.__main__

version = "3.4.0"

if __name__ == "__main__":
    PyInstaller.__main__.run(
        (
            "guardian\\app.py",
            "--onefile",
            "--icon",
            "logo.ico",
            "--uac-admin",
            "--name",
            f"Guardian-{version}",
            "--version-file",
            "version.txt",
            "--specpath",
            "spec",
        )
    )
