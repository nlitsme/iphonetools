# iphonetools
Tools for inspecting iOS firmware images

payloadtool
===========

`payloadtool.py` extracts files from payload files, as found in ios beta firmware.

The payload file can be found in the unzipped firmware path: `AssetData/payloadv2/payload`.

The first 4 bytes read: `pbzx`.

Usage:

    python3 payloadtool.py  payload

Will print a file/dir/link count.

    python3 payloadtool.py -l  payload

Will list the contents of the payload file in a `ls -l` style listing.

    python3 payloadtool.py -o Contents payload
    
Will extract the contents of the payload file into the `Contents` directory.


(c) 2016 Willem Hengeveld <itsme@xs4all.nl>
