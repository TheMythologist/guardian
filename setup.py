from cx_Freeze import setup, Executable
import zipfile
import os
import shutil
# Dependencies are automatically detected, but it might need
# fine tuning.
excludes = [
    'tkinter',
    'zmq',
    'sqlite3',
    'gevent',
    'greenlet',
    'coverage',
    'lzma',
    'cffi',
    'asyncio',
    'bz2',
    'jinja2',
    'xml'
]
zip_exclude_packages = [
    'certifi',
]
buildOptions = dict(packages=[], excludes=excludes, includes=['idna.idnadata', 'codecs'], replace_paths=[("*", "")],
                    optimize=2, zip_include_packages="*", zip_exclude_packages=zip_exclude_packages, silent=True)
base = 'Console'

executables = [
    Executable('app.py', base=base, targetName='Guardian.exe', icon='logo.ico')
]

version = '3.0.0'

try:
    os.remove('build/exe/guardian-{}.zip'.format(version))
except:
    pass
try:
    os.remove('build/exe.win-amd64-3.6/Guardian.exe')
except:
    pass
try:
    shutil.rmtree('build/exe.win-amd64-3.6/lib')
except:
    pass
try:
    os.remove('build/exe.win-amd64-3.6/python36.dll')
except:
    pass
try:
    shutil.copyfile('LICENSE', 'build/exe.win-amd64-3.6/LICENSE')
except:
    pass
setup(name='Guardian',
      version=version,
      description='Firewall',
      options=dict(build_exe=buildOptions),
      executables=executables)


def zip_folder(folder_path, output_path):
    """Zip the contents of an entire folder (with that folder included
    in the archive). Empty subfolders will be included in the archive
    as well.
    """
    parent_folder = os.path.dirname(folder_path)
    # Retrieve the paths of the folder contents.
    contents = os.walk(folder_path, )
    zip_file = zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED)

    for root, folders, files in contents:
        # Include all subfolders, including empty ones.
        for folder_name in folders:
            absolute_path = os.path.join(root, folder_name)
            relative_path = absolute_path.replace(parent_folder + '\\',
                                                  '')
            zip_file.write(absolute_path, relative_path.replace('build/exe.win-amd64-3.6', ''))
        for file_name in files:
            absolute_path = os.path.join(root, file_name)
            relative_path = absolute_path.replace(parent_folder + '\\',
                                                  '')
            zip_file.write(absolute_path, relative_path.replace('build/exe.win-amd64-3.6', ''))
    zip_file.close()

try:
    os.remove('build/exe.win-amd64-3.6/lib/python36.dll')
except:
    pass

zip_folder('build/exe.win-amd64-3.6', 'build\exe\guardian-{}.zip'.format(version))
