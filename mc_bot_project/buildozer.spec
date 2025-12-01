[app]

# (str) Title of your application
title = 4399MCBot

# (str) Package name
package.name = mcbot

# (str) Package domain (needed for android/ios packaging)
package.domain = org.test

# (str) Source code where the main.py live
source.dir = .

# (str) Source code filename (let's use gui.py as the entry point)
source.include_exts = py,png,jpg,kv,atlas,json,txt,md
source.include_patterns = assets/*,netease_auth_server/*

# (list) Application requirements
# comma separated e.g. requirements = sqlite3,kivy
requirements = python3,kivy,asyncio,cryptography,requests,urllib3,chardet,idna,openssl,libffi,cffi

# (str) Custom source folders for requirements
# Sets custom source for any requirements with recipes
# requirements.source.kivy = ../../kivy

# (str) Presplash of the application
# presplash.filename = %(source.dir)s/data/presplash.png

# (str) Icon of the application
# icon.filename = %(source.dir)s/data/icon.png

# (str) Supported orientation (one of landscape, sensorLandscape, portrait or all)
orientation = portrait

# (list) Permissions
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WAKE_LOCK

# (int) Target Android API, should be as high as possible (distutils)
android.api = 33

# (int) Minimum API your APK will support.
android.minapi = 21

# (str) Android NDK version to use
android.ndk = 25b

# (bool) Use --private data storage (True) or --dir public storage (False)
android.private_storage = True

# (str) Android entry point, default is ok for Kivy-based app
# android.entrypoint = org.kivy.android.PythonActivity

# (list) List of Java .jar files to add to the libs so that pyjnius can access
# android.add_jars = foo.jar,bar.jar,common/google.jar.

# (list) List of Java files to add to the android project (can be java or a
# directory containing the files)
# android.add_src =

[buildozer]

# (int) Log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2

# (int) Display warning if buildozer is run as root (0 = False, 1 = True)
warn_on_root = 1
