from cx_Freeze import setup, Executable
import zipfile
import os
import shutil
import sys
# Dependencies are automatically detected, but it might need
# fine tuning.
zip_exclude_packages = [
    'certifi',
    'pydivert',
]
buildOptions = dict(packages=[], includes=['idna.idnadata', 'codecs', 'pydivert'],
                    replace_paths=[("*", "")], optimize=2, zip_include_packages="*",
                    zip_exclude_packages=zip_exclude_packages, silent=True)
executables = [
    Executable('app.py', targetName='Guardian.exe', icon='logo.ico')
]

version = '3.0.2'

build_path = 'build/exe.win-amd64-{}.{}'.format(sys.version_info.major, sys.version_info.minor)

if os.path.exists(build_path):
    shutil.rmtree(build_path)

if not os.path.exists('build/exe'):
    os.makedirs('build/exe')

if os.path.isfile('build/exe/guardian-{}.zip'.format(version)):
    os.remove('build/exe/guardian-{}.zip'.format(version))

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
            zip_file.write(absolute_path, relative_path.replace(build_path, ''))
        for file_name in files:
            absolute_path = os.path.join(root, file_name)
            relative_path = absolute_path.replace(parent_folder + '\\',
                                                  '')
            zip_file.write(absolute_path, relative_path.replace(build_path, ''))
    zip_file.close()

try:
    shutil.copyfile('LICENSE', build_path + '/LICENSE')
    shutil.copyfile('SOURCE', build_path + '/SOURCE')
except:
    pass

zip_folder(build_path, 'build\exe\guardian-{}.zip'.format(version))
