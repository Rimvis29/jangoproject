
Debian
====================
This directory contains files used to package jangod/jango-qt
for Debian-based Linux systems. If you compile jangod/jango-qt yourself, there are some useful files here.

## jango: URI support ##


jango-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install jango-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your jango-qt binary to `/usr/bin`
and the `../../share/pixmaps/jango128.png` to `/usr/share/pixmaps`

jango-qt.protocol (KDE)

