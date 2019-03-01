# -*- coding: utf-8 -*-
#
# GPL License and Copyright Notice ============================================
#  This file is part of Wrye Bash.
#
#  Wrye Bash is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  Wrye Bash is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Wrye Bash; if not, write to the Free Software Foundation,
#  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#  Wrye Bash copyright (C) 2005-2009 Wrye, 2010-2019 Wrye Bash Team
#  https://github.com/wrye-bash
#
# =============================================================================
"""Script extender cosave files. They are composed of a header and script
extender plugin chunks which, in turn are composed of chunks. We need to
read them to log stats and write them to remap espm masters. We only handle
renaming of the masters of the xSE plugin chunk itself and of the Pluggy chunk.
"""
from ..bolt import sio, GPath, decode, encode, unpack_string, unpack_int, \
    unpack_short, unpack_4s, unpack_byte, unpack_str16, struct_pack, \
    struct_unpack, deprint
from ..exception import FileError


# Small helper functions for quickly packing and unpacking
def _pack(buff, fmt, *args): buff.write(struct_pack(fmt, *args))
# TODO(inf) Replace with unpack_many
def _unpack(ins, fmt, size): return struct_unpack(fmt, ins.read(size))

class _AHeader(object):
    """Abstract base class for cosave headers."""
    savefile_tag = 'OVERRIDE'
    __slots__ = ()

    def __init__(self, ins, cosave_path):
        """
        The base constructor for headers checks if the expected save file tag
        for this header matches the actual tag found in the file.

        :param ins: The input stream to read from.
        :param cosave_path: The path to the cosave.
        """
        actual_tag = unpack_string(ins, len(self.savefile_tag))
        if actual_tag != self.savefile_tag:
            raise FileError(cosave_path, u'Header tag wrong: got %r, but '
                                         u'expected %r' %
                            (actual_tag, self.savefile_tag))

    def write_header(self, out):
        """
        Writes this header to the specified output stream. The base method just
        writes the save file tag.

        :param out: The output stream to write to.
        """
        out.write(self.savefile_tag)

class _xSEHeader(_AHeader):
    """Header for xSE cosaves."""
    __slots__ = ('format_version', 'se_version', 'se_minor_version',
                 'game_version', 'num_plugins')

    # num_plugins: the xSE plugins the cosave knows about - including xSE itself
    def __init__(self, ins, cosave_path):
        super(_xSEHeader, self).__init__(ins, cosave_path)
        self.format_version = unpack_int(ins)
        self.se_version = unpack_short(ins)
        self.se_minor_version = unpack_short(ins)
        self.game_version = unpack_int(ins)
        self.num_plugins = unpack_int(ins)

    def write_header(self, out):
        super(_xSEHeader, self).write_header(out)
        _pack(out, '=I', self.format_version)
        _pack(out, '=H', self.se_version)
        _pack(out, '=H', self.se_minor_version)
        _pack(out, '=I', self.game_version)

class _PluggyHeader(_AHeader):
    """Header for pluggy cosaves. Just checks save file tag and version."""
    savefile_tag = 'PluggySave'
    _max_supported_version = 0x0105000
    __slots__ = ()

    def __init__(self, ins, cosave_path):
        super(_PluggyHeader, self).__init__(ins, cosave_path)
        version = unpack_int(ins)
        if version > self._max_supported_version:
            raise FileError(cosave_path, u'Version of pluggy save file format '
                                         u'is too new - only versions up to '
                                         u'1.6.0000 are supported.')

    def write_header(self, out):
        super(_PluggyHeader, self).write_header(out)
        _pack(out, '=I', self._max_supported_version)

class _AChunk(object):
    _esm_encoding = 'cp1252' # TODO ask!
    __slots__ = ()

    def log_chunk(self, log, ins, save_masters, espmMap):
        """
        :param save_masters: the espm masters of the save, used in xSE chunks
        :param espmMap: a dict populated in pluggy chunks
        :type log: bolt.Log
        """

    def chunk_map_master(self, master_renames_dict, plugin_chunk):
        """Rename the espm masters - for xSE and Pluggy chunks.

        :param master_renames_dict: mapping of old to new espm names
        :param plugin_chunk: the plugin_chunk this chunk belongs to
        """

class _xSEPluginChunk(_AChunk):
    _espm_chunk_type = {'SDOM'}
    __slots__ = ('chunkType', 'chunkVersion', 'chunkLength', 'chunkData')

    def __init__(self, ins):
        self.chunkType = unpack_4s(ins)
        self.chunkVersion = unpack_int(ins)
        self.chunkLength = unpack_int(ins) # the length of the chunk data block
        self.chunkData = ins.read(self.chunkLength)

    def log_chunk(self, log, ins, save_masters, espmMap):
        chunkType = self.chunkType
        if chunkType == 'RVTS':
            #--OBSE String
            modIndex, stringID, stringLength, = _unpack(ins, '=BIH', 7)
            stringData = decode(ins.read(stringLength))
            log(u'    ' + _(u'Mod :') + u'  %02X (%s)' % (
                modIndex, save_masters[modIndex].s))
            log(u'    ' + _(u'ID  :') + u'  %u' % stringID)
            log(u'    ' + _(u'Data:') + u'  %s' % stringData)
        elif chunkType == 'RVRA':
            #--OBSE Array
            modIndex, arrayID, keyType, isPacked, = _unpack(ins, '=BIBB', 7)
            if modIndex == 255:
                log(_(u'    Mod :  %02X (Save File)') % modIndex)
            else:
                log(_(u'    Mod :  %02X (%s)') % (
                    modIndex, save_masters[modIndex].s))
            log(_(u'    ID  :  %u') % arrayID)
            if keyType == 1: #Numeric
                if isPacked:
                    log(_(u'    Type:  Array'))
                else:
                    log(_(u'    Type:  Map'))
            elif keyType == 3:
                log(_(u'    Type:  StringMap'))
            else:
                log(_(u'    Type:  Unknown'))
            if self.chunkVersion >= 1:
                numRefs, = _unpack(ins, '=I', 4)
                if numRefs > 0:
                    log(u'    Refs:')
                    for x in range(numRefs):
                        refModID, = _unpack(ins, '=B', 1)
                        if refModID == 255:
                            log(_(u'      %02X (Save File)') % refModID)
                        else:
                            log(u'      %02X (%s)' % (
                                refModID, save_masters[refModID].s))
            numElements, = _unpack(ins, '=I', 4)
            log(_(u'    Size:  %u') % numElements)
            for i in range(numElements):
                if keyType == 1:
                    key, = _unpack(ins, '=d', 8)
                    keyStr = u'%f' % key
                elif keyType == 3:
                    keyLen, = _unpack(ins, '=H', 2)
                    key = ins.read(keyLen)
                    keyStr = decode(key)
                else:
                    keyStr = 'BAD'
                dataType, = _unpack(ins, '=B', 1)
                if dataType == 1:
                    data, = _unpack(ins, '=d', 8)
                    dataStr = u'%f' % data
                elif dataType == 2:
                    data, = _unpack(ins, '=I', 4)
                    dataStr = u'%08X' % data
                elif dataType == 3:
                    dataLen, = _unpack(ins, '=H', 2)
                    data = ins.read(dataLen)
                    dataStr = decode(data)
                elif dataType == 4:
                    data, = _unpack(ins, '=I', 4)
                    dataStr = u'%u' % data
                log(u'    [%s]:%s = %s' % (keyStr, (
                u'BAD', u'NUM', u'REF', u'STR', u'ARR')[dataType],
                                           dataStr))

    def chunk_map_master(self, master_renames_dict, plugin_chunk):
        if self.chunkType not in self._espm_chunk_type:
            return
        with sio(self.chunkData) as ins:
            num_of_masters = unpack_byte(ins) # this won't change
            with sio() as out:
                _pack(out, 'B', num_of_masters)
                while ins.tell() < len(self.chunkData):
                    modName = GPath(unpack_str16(ins))
                    modName = master_renames_dict.get(modName, modName)
                    modname_str = encode(modName.s,
                                         firstEncoding=self._esm_encoding)
                    _pack(out, '=H', len(modname_str))
                    out.write(modname_str)
                self.chunkData = out.getvalue()
        old_chunk_length = self.chunkLength
        self.chunkLength = len(self.chunkData)
        plugin_chunk.plugin_data_size += self.chunkLength - old_chunk_length # Todo Test

class _xSEPluggyChunk(_xSEPluginChunk):
    def log_chunk(self, log, ins, save_masters, espMap):
        chunkVersion = self.chunkVersion
        chunkBuff = self.chunkData
        chunkTypeNum, = struct_unpack('=I', self.chunkType)
        if chunkTypeNum == 1:
            #--Pluggy TypeESP
            log(_(u'    Pluggy ESPs'))
            log(_(u'    EID   ID    Name'))
            while ins.tell() < len(chunkBuff):
                if chunkVersion == 2:
                    espId, modId, = _unpack(ins, '=BB', 2)
                    log(u'    %02X    %02X' % (espId, modId))
                    espMap[modId] = espId
                else:  #elif chunkVersion == 1"
                    espId, modId, modNameLen, = _unpack(ins, '=BBI', 6)
                    modName = ins.read(modNameLen)
                    log(u'    %02X    %02X    %s' % (espId, modId, modName))
                    espMap[modId] = modName  # was [espId]
        elif chunkTypeNum == 2:
            #--Pluggy TypeSTR
            log(_(u'    Pluggy String'))
            strId, modId, strFlags, = _unpack(ins, '=IBB', 6)
            strData = ins.read(len(chunkBuff) - ins.tell())
            log(u'      ' + _(u'StrID :') + u' %u' % strId)
            log(u'      ' + _(u'ModID :') + u' %02X %s' % (
                modId, espMap[modId] if modId in espMap else u'ERROR',))
            log(u'      ' + _(u'Flags :') + u' %u' % strFlags)
            log(u'      ' + _(u'Data  :') + u' %s' % strData)
        elif chunkTypeNum == 3:
            #--Pluggy TypeArray
            log(_(u'    Pluggy Array'))
            arrId, modId, arrFlags, arrSize, = _unpack(ins, '=IBBI', 10)
            log(_(u'      ArrID : %u') % (arrId,))
            log(_(u'      ModID : %02X %s') % (
                modId, espMap[modId] if modId in espMap else u'ERROR',))
            log(_(u'      Flags : %u') % (arrFlags,))
            log(_(u'      Size  : %u') % (arrSize,))
            while ins.tell() < len(chunkBuff):
                elemIdx, elemType, = _unpack(ins, '=IB', 5)
                elemStr = ins.read(4)
                if elemType == 0:  #--Integer
                    elem, = struct_unpack('=i', elemStr)
                    log(u'        [%u]  INT  %d' % (elemIdx, elem,))
                elif elemType == 1:  #--Ref
                    elem, = struct_unpack('=I', elemStr)
                    log(u'        [%u]  REF  %08X' % (elemIdx, elem,))
                elif elemType == 2:  #--Float
                    elem, = struct_unpack('=f', elemStr)
                    log(u'        [%u]  FLT  %08X' % (elemIdx, elem,))
        elif chunkTypeNum == 4:
            #--Pluggy TypeName
            log(_(u'    Pluggy Name'))
            refId, = _unpack(ins, '=I', 4)
            refName = ins.read(len(chunkBuff) - ins.tell())
            newName = u''
            for c in refName:
                ch = c if (c >= chr(0x20)) and (c < chr(0x80)) else '.'
                newName = newName + ch
            log(_(u'      RefID : %08X') % refId)
            log(_(u'      Name  : %s') % decode(newName))
        elif chunkTypeNum == 5:
            #--Pluggy TypeScr
            log(_(u'    Pluggy ScreenSize'))
            #UNTESTED - uncomment following line to skip this record type
            #continue
            scrW, scrH, = _unpack(ins, '=II', 8)
            log(_(u'      Width  : %u') % scrW)
            log(_(u'      Height : %u') % scrH)
        elif chunkTypeNum == 6:
            #--Pluggy TypeHudS
            log(u'    ' + _(u'Pluggy HudS'))
            #UNTESTED - uncomment following line to skip this record type
            #continue
            hudSid, modId, hudFlags, hudRootID, hudShow, hudPosX, hudPosY, \
            hudDepth, hudScaleX, hudScaleY, hudAlpha, hudAlignment, \
            hudAutoScale, = _unpack(ins, '=IBBBBffhffBBB', 29)
            hudFileName = decode(ins.read(len(chunkBuff) - ins.tell()))
            log(u'      ' + _(u'HudSID :') + u' %u' % hudSid)
            log(u'      ' + _(u'ModID  :') + u' %02X %s' % (
                modId, espMap[modId] if modId in espMap else u'ERROR',))
            log(u'      ' + _(u'Flags  :') + u' %02X' % hudFlags)
            log(u'      ' + _(u'RootID :') + u' %u' % hudRootID)
            log(u'      ' + _(u'Show   :') + u' %02X' % hudShow)
            log(u'      ' + _(u'Pos    :') + u' %f,%f' % (hudPosX, hudPosY,))
            log(u'      ' + _(u'Depth  :') + u' %u' % hudDepth)
            log(u'      ' + _(u'Scale  :') + u' %f,%f' % (
                hudScaleX, hudScaleY,))
            log(u'      ' + _(u'Alpha  :') + u' %02X' % hudAlpha)
            log(u'      ' + _(u'Align  :') + u' %02X' % hudAlignment)
            log(u'      ' + _(u'AutoSc :') + u' %02X' % hudAutoScale)
            log(u'      ' + _(u'File   :') + u' %s' % hudFileName)
        elif chunkTypeNum == 7:
            #--Pluggy TypeHudT
            log(_(u'    Pluggy HudT'))
            #UNTESTED - uncomment following line to skip this record type
            #continue
            hudTid, modId, hudFlags, hudShow, hudPosX, hudPosY, hudDepth, \
                = _unpack(ins, '=IBBBffh', 17)
            hudScaleX, hudScaleY, hudAlpha, hudAlignment, hudAutoScale, \
            hudWidth, hudHeight, hudFormat, = _unpack(ins, '=ffBBBIIB', 20)
            hudFontNameLen, = _unpack(ins, '=I', 4)
            hudFontName = decode(ins.read(hudFontNameLen))
            hudFontHeight, hudFontWidth, hudWeight, hudItalic, hudFontR, \
            hudFontG, hudFontB, = _unpack(ins, '=IIhBBBB', 14)
            hudText = decode(ins.read(len(chunkBuff) - ins.tell()))
            log(u'      ' + _(u'HudTID :') + u' %u' % hudTid)
            log(u'      ' + _(u'ModID  :') + u' %02X %s' % (
                modId, espMap[modId] if modId in espMap else u'ERROR',))
            log(u'      ' + _(u'Flags  :') + u' %02X' % hudFlags)
            log(u'      ' + _(u'Show   :') + u' %02X' % hudShow)
            log(u'      ' + _(u'Pos    :') + u' %f,%f' % (hudPosX, hudPosY,))
            log(u'      ' + _(u'Depth  :') + u' %u' % hudDepth)
            log(u'      ' + _(u'Scale  :') + u' %f,%f' % (
                hudScaleX, hudScaleY,))
            log(u'      ' + _(u'Alpha  :') + u' %02X' % hudAlpha)
            log(u'      ' + _(u'Align  :') + u' %02X' % hudAlignment)
            log(u'      ' + _(u'AutoSc :') + u' %02X' % hudAutoScale)
            log(u'      ' + _(u'Width  :') + u' %u' % hudWidth)
            log(u'      ' + _(u'Height :') + u' %u' % hudHeight)
            log(u'      ' + _(u'Format :') + u' %u' % hudFormat)
            log(u'      ' + _(u'FName  :') + u' %s' % hudFontName)
            log(u'      ' + _(u'FHght  :') + u' %u' % hudFontHeight)
            log(u'      ' + _(u'FWdth  :') + u' %u' % hudFontWidth)
            log(u'      ' + _(u'FWeigh :') + u' %u' % hudWeight)
            log(u'      ' + _(u'FItal  :') + u' %u' % hudItalic)
            log(u'      ' + _(u'FRGB   :') + u' %u,%u,%u' % (
                hudFontR, hudFontG, hudFontB,))
            log(u'      ' + _(u'FText  :') + u' %s' % hudText)

    def chunk_map_master(self, master_renames_dict, plugin_chunk):
        chunkTypeNum, = struct_unpack('=I', self.chunkType)
        if chunkTypeNum != 1:
            return # TODO confirm this is the espm chunk for Pluggy
                   # It is not. 0 is, according to the downloadable save file
                   # documentation.
        with sio(self.chunkData) as ins:
            with sio() as out:
                while ins.tell() < len(self.chunkData):
                    espId, modId, modNameLen, = _unpack(ins, '=BBI', 6)
                    modName = GPath(ins.read(modNameLen))
                    modName = master_renames_dict.get(modName, modName)
                    _pack(out, '=BBI', espId, modId, len(modName.s))
                    out.write(encode(modName.cs, ##: why LowerCase ??
                                     firstEncoding=self._esm_encoding))
                self.chunkData = out.getvalue()
        old_chunk_length = self.chunkLength
        self.chunkLength = len(self.chunkData)
        plugin_chunk.plugin_data_size += self.chunkLength - old_chunk_length # Todo Test

class _PluggyChunk(_AChunk):
    pass

class _xSEChunk(_AChunk):
    """A single xSE chunk, composed of _xSEPluginChunk (and potentially
    _PluggyChunk) objects."""
    _xse_signature = 0x1400 # signature (aka opcodeBase) of xSE plugin itself
    _pluggy_signature = None # signature (aka opcodeBase) of Pluggy plugin
    __slots__ = ('plugin_signature', 'num_plugin_chunks', 'plugin_data_size',
                 'plugin_chunks')

    def __init__(self, ins):
        self.plugin_signature = unpack_int(ins) # aka opcodeBase on pre papyrus
        self.num_plugin_chunks = unpack_int(ins)
        self.plugin_data_size = unpack_int(ins) # update it if you edit chunks
        self.plugin_chunks = []
        chunk_type = self._get_plugin_chunk_type(self._xse_signature,
                                                 self._pluggy_signature)
        for _ in xrange(self.num_plugin_chunks):
            self.plugin_chunks.append(chunk_type(ins))

    def _get_plugin_chunk_type(self, xse_signature, pluggy_signature):
        if self.plugin_signature == xse_signature: return _xSEPluginChunk
        if self.plugin_signature == pluggy_signature: return _xSEPluggyChunk
        return _AChunk

class ACoSaveFile(object):
    chunk_type = _AChunk
    header_type = _AHeader
    __slots__ = ('cosave_path', 'cosave_header', 'chunks')

    def __init__(self, cosave_path):
        self.cosave_path = cosave_path
        with cosave_path.open('rb') as ins:
            self.cosave_header = self.header_type(ins, cosave_path)
            self.chunks = self.load_chunks(ins)

    def load_chunks(self, ins):
        pass

class xSECoSave(ACoSaveFile):
    chunk_type = _xSEChunk
    header_type = _xSEHeader
    __slots__ = ()

    def load_chunks(self, ins):
        loaded_chunks = []
        for _ in xrange(self.cosave_header.num_plugins):
            loaded_chunks.append(self.chunk_type(ins))
        return loaded_chunks

    def map_masters(self, master_renames_dict):
        for plugin_chunk in self.chunks:
            for chunk in plugin_chunk.plugin_chunks: # TODO avoid scanning all chunks
                chunk.chunk_map_master(master_renames_dict, plugin_chunk)

    def logStatObse(self, log, save_masters):
        """Print stats to log."""
        #--Header
        my_header = self.cosave_header # type: _xSEHeader
        log.setHeader(_(u'Header'))
        log(u'=' * 80)
        log(_(u'  Format version:   %08X') % (my_header.format_version,))
        log(_(u'  %s version:      %u.%u') % (
            my_header.savefile_tag, my_header.se_version,
            my_header.se_minor_version,))
        log(_(u'  Game version:     %08X') % (my_header.game_version,))
        #--Plugins
        for plugin_ch in self.chunks: # type: _xSEChunk
            plugin_sig = plugin_ch.plugin_signature
            log.setHeader(_(u'Plugin opcode=%08X chunkNum=%u') % (
                plugin_sig, plugin_ch.num_plugin_chunks,))
            log(u'=' * 80)
            log(_(u'  Type  Ver   Size'))
            log(u'-' * 80)
            espMap = {}
            for ch in plugin_ch.plugin_chunks: # type: _xSEPluginChunk
                chunkTypeNum, = struct_unpack('=I',ch.chunkType)
                if ch.chunkType[0] >= ' ' and ch.chunkType[3] >= ' ': # HUH ?
                    log(u'  %4s  %-4u  %08X' % (
                        ch.chunkType, ch.chunkVersion, ch.chunkLength))
                else:
                    log(u'  %04X  %-4u  %08X' % (
                        chunkTypeNum, ch.chunkVersion, ch.chunkLength))
                with sio(ch.chunkData) as ins:
                    ch.log_chunk(log, ins, save_masters, espMap)

    def write_cosave(self, out_path):
        mtime = self.cosave_path.mtime # must exist !
        with sio() as buff:
            self.cosave_header.write_header(buff)
            #--Plugins
            _pack(buff,'=I', len(self.chunks))
            for plugin_ch in self.chunks: # type: _xSEChunk
                _pack(buff, '=I', plugin_ch.plugin_signature)
                _pack(buff, '=I', plugin_ch.num_plugin_chunks)
                _pack(buff, '=I', plugin_ch.plugin_data_size)
                for chunk in plugin_ch.plugin_chunks: # type: _xSEPluginChunk
                    buff.write(chunk.chunkType)
                    _pack(buff, '=2I', chunk.chunkVersion, chunk.chunkLength)
                    buff.write(chunk.chunkData)
            text = buff.getvalue()
        with out_path.open('wb') as out:
            out.write(text)
        out_path.mtime = mtime

    def write_cosave_safe(self):
        """Write to a tmp file first so if that fails we won't delete the
        cosave."""
        self.write_cosave(self.cosave_path.temp)
        self.cosave_path.untemp()

# Factory
def get_cosave_type(game_fsName):
    """:rtype: type"""
    if game_fsName == u'Oblivion':
        _xSEHeader.savefile_tag = 'OBSE'
        _xSEChunk._pluggy_signature = 0x2330
    elif game_fsName == u'Skyrim':
        _xSEHeader.savefile_tag = 'SKSE'
        _xSEChunk._xse_signature = 0x0
    elif game_fsName == u'Skyrim Special Edition':
        _xSEHeader.savefile_tag = 'SKSE'
        _xSEChunk._xse_signature = 0x0
        _xSEPluginChunk._espm_chunk_type = {'SDOM', 'DOML'}
    elif game_fsName == u'Fallout4':
        _xSEHeader.savefile_tag = 'F4SE'
        _xSEChunk._xse_signature = 0x0
        _xSEPluginChunk._espm_chunk_type = {'SDOM', 'DOML'}
    elif game_fsName == u'Fallout3':
        _xSEHeader.savefile_tag = 'FOSE'
    elif game_fsName == u'FalloutNV':
        _xSEHeader.savefile_tag = 'NVSE'
    return xSECoSave

#------------------------------------------------------------------------------
class PluggyFile(ACoSaveFile):
    """Represents a .pluggy cofile for saves. Used for editing masters list."""
    chunk_type = _PluggyChunk
    header_type = _PluggyHeader

    def __init__(self, cosave_path):
        super(PluggyFile, self).__init__(cosave_path)
        self.version = None
        self._plugins = None
        self.other = None
        self.valid = False

    def mapMasters(self,masterMap):
        """Update plugin names according to masterMap."""
        if not self.valid:
            raise FileError(self.cosave_path.tail, u"File not initialized.")
        self._plugins = [(x, y, masterMap.get(z,z)) for x,y,z in self._plugins]

    def load(self):
        """Read file."""
        import binascii
        path_size = self.cosave_path.size
        with self.cosave_path.open('rb') as ins:
            buff = ins.read(path_size-4)
            crc32, = struct_unpack('=i', ins.read(4))
        crcNew = binascii.crc32(buff)
        if crc32 != crcNew:
            raise FileError(self.cosave_path.tail,
                            u'CRC32 file check failed. File: %X, Calc: %X' % (
                                crc32, crcNew))
        #--Header
        with sio(buff) as ins:
            if ins.read(10) != 'PluggySave':
                raise FileError(self.cosave_path.tail, u'File tag != "PluggySave"')
            self.version, = _unpack(ins, 'I', 4)
            #--Reject versions earlier than 1.02
            if self.version < 0x01020000:
                raise FileError(self.cosave_path.tail,
                                u'Unsupported file version: %X' % self.version)
            #--Plugins
            self._plugins = []
            type, = _unpack(ins, '=B', 1)
            if type != 0:
                raise FileError(self.cosave_path.tail,
                                u'Expected plugins record, but got %d.' % type)
            count, = _unpack(ins, '=I', 4)
            for x in range(count):
                espid,index,modLen = _unpack(ins, '=2BI', 6)
                modName = GPath(decode(ins.read(modLen)))
                self._plugins.append((espid, index, modName))
            #--Other
            self.other = ins.getvalue()[ins.tell():]
        deprint(struct_unpack('I', self.other[-4:]), self.cosave_path.size-8)
        #--Done
        self.valid = True

    def save(self,path=None,mtime=0):
        """Saves."""
        import binascii
        if not self.valid:
            raise FileError(self.cosave_path.tail, u"File not initialized.")
        #--Buffer
        with sio() as buff:
            #--Save
            buff.write('PluggySave')
            _pack(buff, '=I', self.version)
            #--Plugins
            _pack(buff, '=B', 0)
            _pack(buff, '=I', len(self._plugins))
            for (espid,index,modName) in self._plugins:
                modName = encode(modName.cs)
                _pack(buff, '=2BI', espid, index, len(modName))
                buff.write(modName)
            #--Other
            buff.write(self.other)
            #--End control
            buff.seek(-4,1)
            _pack(buff, '=I', buff.tell())
            #--Save
            path = path or self.cosave_path
            mtime = mtime or path.exists() and path.mtime
            text = buff.getvalue()
            with path.open('wb') as out:
                out.write(text)
                out.write(struct_pack('i', binascii.crc32(text)))
        path.mtime = mtime

    def safeSave(self):
        """Save data to file safely."""
        self.save(self.cosave_path.temp,self.cosave_path.mtime)
        self.cosave_path.untemp()
