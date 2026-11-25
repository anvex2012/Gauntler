# Creato da anvex2012
# Layout of the macOS install window (.dmg), used by scripts/package-all.js through dmgbuild.
# Values come from defines: -D app=... -D background=... -D icon=...
import os

application = defines['app']
appname = os.path.basename(application)

format = 'UDZO'
filesystem = 'HFS+'
files = [application]
symlinks = {'Applicazioni': '/Applications'}
hide_extensions = [appname]
icon = defines.get('icon')

# Finder window: background with the instructions, two large icons, no toolbar or sidebar
background = defines['background']
window_rect = ((200, 120), (660, 452))  # 420 of content + title bar
default_view = 'icon-view'
show_toolbar = False
show_status_bar = False
show_tab_view = False
show_pathbar = False
show_sidebar = False
show_icon_preview = False
include_icon_view_settings = True
arrange_by = None
icon_size = 104
text_size = 13
label_pos = 'bottom'
icon_locations = {
    appname: (170, 175),
    'Applicazioni': (490, 175),
}
