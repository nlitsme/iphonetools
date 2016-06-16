"""
Tool for extracting files from an ios payload file ( AssetData/payloadv2/payload )

This file starts with the magic string 'pbzx', followed by a 64bit value 0x1000000.

followed by xz compressed chunks, each preceeded with two 64bit values:
    - expanded size
    - compressed size

the decompressed chunks concatenated together form an archive containing
the files for iOS.

(C) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import division, print_function
import struct
import time
import os
import lzma


class Header:
    """ empty class used as struct. """
    pass


def readheader(fh):
    """ reads the 30 byte header """
    hdr = fh.read(30)
    if len(hdr) == 0:
        return
    o = Header()
    o.unk1, o.type, o.filesize, o.timestamp, o.attr, o.namelen, o.uid, o.gid, o.filemode = struct.unpack(">BBQQLHhhH", hdr)
    # unk1 is always 0x10
    # attr: 0, 0x20, 0x8000
    # type:  1=file, 2=dir, 3=symlink
    o.name = fh.read(o.namelen).decode('utf-8')

    return o


def makedirs(fullpath):
    """
    Create non existing subdirectories of path, like python3 os.makedirs with exist_ok=True
    """
    path = ""
    for part in fullpath.split('/'):
        if path:
            path += '/'
        path += part
        if not os.access(path, os.F_OK):
            os.mkdir(path)


def savedata(name, fh, size):
    """ save <size> bytes from <fh> to a file named <name> """
    makedirs(os.path.dirname(name))
    with open(name, "wb") as of:
        while size > 0:
            wanted = min(0x100000, size)
            data = fh.read(wanted)
            if len(data) == 0:
                break
            of.write(data)

            size -= wanted


def createlink(name, content):
    """ create a symlink <name> pointing to <content> """
    makedirs(os.path.dirname(name))
    os.symlink(content, name)


def processpayload(fh, args):
    """ process payload, optionally listing or creating files """
    entrytypes = {1:"file", 2:"dir", 3:"link"}

    def entryname(typ):
        if typ in entrytypes:
            return entrytypes[typ]
        return "?%02x?" % typ

    def modestring(mode):
        # todo .. return str like: lrwxr-xr-x
        return "%06o" % mode

    count = {1:0, 2:0, 3:0}
    while True:
        hdr = readheader(fh)
        if not hdr:
            break
        suffix = ""
        if hdr.type == 3:
            link = fh.read(hdr.filesize).decode('utf-8')
            suffix = " -> %s" % link
            if args.output:
                createlink(args.output+'/'+hdr.name, link)
        elif hdr.type == 1 and args.output:
            savedata(args.output+'/'+hdr.name, fh, hdr.filesize)
        else:
            fh.seek(hdr.filesize, 1)

        if args.list:
            print("%-4s %s [%08x] %5d%5d %12d %s  %s%s" % (entryname(hdr.type), modestring(hdr.filemode), hdr.attr, hdr.uid, hdr.gid, hdr.filesize, time.ctime(hdr.timestamp), hdr.name, suffix))
            if hdr.unk1 != 0x10:
                print("NOTE: field unk1 == 0x%02x (expected 0x10)" % hdr.unk1)
        count[hdr.type] += 1
    print("Found %d files, %d dirs, %d links" % (count[1], count[2], count[3]))


class pbzx_decompressor:
    """ Stream decompressing the outer layer of the payload file """
    def __init__(self, fh):
        self.fh = fh

        filehdr = fh.read(12)
        magic, maxchunk = struct.unpack(">4sQ", filehdr)
        if magic != b'pbzx':
            raise Exception("not a pbzx payload")

        self.buffer = None
        self.bufferpos = 0

    def next(self):
        """ read and decompress next chunk """
        chunkhdr = self.fh.read(16)
        if len(chunkhdr) == 0:
            return
        fullsize, compsize = struct.unpack(">QQ", chunkhdr)

        xzdata = self.fh.read(compsize)
        return lzma.decompress(xzdata)

    def read(self, size):
        """ read bytes from stream """
        data = b""
        while size > 0:
            if self.buffer is None:
                self.buffer = self.next()
                self.bufferpos = 0
            if self.buffer is None:
                return data
            want = min(size, len(self.buffer)-self.bufferpos)
            endpos = self.bufferpos+want
            data += self.buffer[self.bufferpos:endpos]
            if endpos == len(self.buffer):
                self.buffer = None
                self.bufferpos = None
            else:
                self.bufferpos = endpos

            size -= want
        return data

    def seek(self, size, whence):
        """ seek forward on stream """
        if whence != 1 or size < 0:
            raise Exception("only relative forward seek supported")

        while size > 0:
            if self.buffer is None:
                self.buffer = self.next()
                self.bufferpos = 0
            if self.buffer is None:
                return
            want = min(size, len(self.buffer)-self.bufferpos)
            self.bufferpos += want
            if self.bufferpos == len(self.buffer):
                self.buffer = None
                self.bufferpos = None

            size -= want


def main():
    import argparse
    parser = argparse.ArgumentParser(description='payloadtool')
    parser.add_argument('--output', '-o', type=str, help='Save files in directory')
    parser.add_argument('--list', '-l', action='store_true', help='list contents')
    parser.add_argument('payload', type=str, nargs=1)
    args = parser.parse_args()

    with open(args.payload[0], "rb") as fh:
        processpayload(pbzx_decompressor(fh), args)

if __name__ == '__main__':
    main()
