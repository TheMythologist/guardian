import PyInstaller.__main__

version = "3.4.1"


def build() -> None:
    PyInstaller.__main__.run(
        (
            "guardian\\__main__.py",
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
