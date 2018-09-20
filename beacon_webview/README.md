# Beacon Webview

NOTE: This is early test code. It works, but may need tuning for production

Display beacons in a graphical webview

Uses a python3 script to convert the exported CSV to the JSON needed for for the webview display

Requires the csv and json modules

## Features

- CSV to JSON for D3 graph processing
- Displays link relationship (HTTP/SMB) for connected beacons
- Highlights linked beacon
- Hover over displays beacon info

![](webview.png)

![](webview1.gif)

![](webview2.gif)

## Quickstart

1) Import the script

    import export_beacons.cna

2) Use the script console to export the data

    makeWebview

3) Start web server in webview directory

    python3 -m http.server 8000

4) Browse the local web server

    http://localhost:8000/beacons.html



