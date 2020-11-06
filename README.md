# Cobalt Strike Aggressor Scripts

Collection of Cobalt Strike Aggressor Scripts

## enumerate.cna

Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in API-only commands.

Additionally, adds a basic `enumerate` alias for Linux based systems in SSH sessions.

## wmi_msbuild

Extends Beacon's `jump` command by adding a `wmi_msbuild` option that uses remote WMI to create a new msbuild process and execute an XML file generated via python with encrypted Beacon stageless shellcode. See wmi_msbuild.cna for OPSEC notes and usage.

Adapted by @andrewchiles for CS 4.0+ jump and removed PowerLessShell requirement
Original Authors: 		Alyssa (ramen0x3f), MrT__F version for PowerLessShell
