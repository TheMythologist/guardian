import os
import shutil
import sys
import zipfile

from cx_Freeze import Executable, setup

# Dependencies are automatically detected, but it might need
# fine tuning.
zip_exclude_packages = [
    "certifi",
    "pydivert",
]
buildOptions = dict(
    packages=[],
    includes=["idna.idnadata", "codecs", "pydivert"],
    replace_paths=[("*", "")],
    optimize=2,
    zip_include_packages="*",
    zip_exclude_packages=zip_exclude_packages,
    silent=True,
)
executables = [
    Executable("app.py", target_name="Guardian.exe", icon="logo.ico", uac_admin=True)
]


version = "3.1.0b5-fastload-fix"
version_number = "3.1.0.5"

build_path = "build/exe.win-amd64-{}.{}".format(
    sys.version_info.major, sys.version_info.minor
)

if os.path.exists(build_path):
    shutil.rmtree(build_path)

if not os.path.exists("build/exe"):
    os.makedirs("build/exe")

if os.path.isfile("build/exe/guardian-{}.zip".format(version)):
    os.remove("build/exe/guardian-{}.zip".format(version))

setup(
    name="Guardian",
    version=version_number,
    description="Firewall",
    options=dict(build_exe=buildOptions),
    executables=executables,
)


def zip_folder(folder_path, output_path):
    """Zip the contents of an entire folder (with that folder included
    in the archive). Empty subfolders will be included in the archive
    as well.
    """
    parent_folder = os.path.dirname(folder_path)
    # Retrieve the paths of the folder contents.
    contents = os.walk(
        folder_path,
    )
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, folders, files in contents:
            # Include all subfolders, including empty ones.
            for folder_name in folders:
                absolute_path = os.path.join(root, folder_name)
                relative_path = absolute_path.replace(parent_folder + "\\", "")
                zip_file.write(absolute_path, relative_path.replace(build_path, ""))
            for file_name in files:
                absolute_path = os.path.join(root, file_name)
                relative_path = absolute_path.replace(parent_folder + "\\", "")
                zip_file.write(absolute_path, relative_path.replace(build_path, ""))


shutil.copyfile("LICENSE", f"{build_path}/LICENSE")
shutil.copyfile("SOURCE", f"{build_path}/SOURCE")

zip_folder(build_path, rf"build\exe\guardian-{version}.zip")
