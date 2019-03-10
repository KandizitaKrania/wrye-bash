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
from ..exception import AbstractError, FileError


#------------------------------------------------------------------------------
# Utilities
def _pack(buff, fmt, *args): buff.write(struct_pack(fmt, *args))
# TODO(inf) Replace with unpack_many
def _unpack(ins, fmt, size): return struct_unpack(fmt, ins.read(size))

class _Remappable(object):
    """Mixin for objects inside cosaves that have to be updated when the names
    of one or more plugin files referenced in the cosave has been changed."""
    def remap_plugins(self, plugin_renames):
        """
        Remaps the names of relevant plugin entries in this object.

        :param plugin_renames: A dictionary containing the renames: key is the
                               name of the plugin before the renaming, value is
                               the name afterwards.
        """
        raise AbstractError()

#------------------------------------------------------------------------------
# Headers
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

    def dump_header(self, log, save_masters):
        """
        Dumps information from this header into the specified log. The default
        implementation only writes out a 'Header' heading and a separator.

        :param log: A bolt.Log instance to write to.
        :param save_masters: A list of the masters of the save file that this
                             cosave belongs to.
        """
        log.setHeader(_(u'%s Header') % self.savefile_tag)
        log(u'=' * 80)

class _xSEHeader(_AHeader):
    """Header for xSE cosaves."""
    __slots__ = ('format_version', 'se_version', 'se_minor_version',
                 'game_version', 'num_plugin_chunks')

    # num_plugin_chunks is the number of xSE plugin chunks contained in the
    # cosave. Note that xSE itself also counts as one!
    def __init__(self, ins, cosave_path):
        super(_xSEHeader, self).__init__(ins, cosave_path)
        self.format_version = unpack_int(ins)
        self.se_version = unpack_short(ins)
        self.se_minor_version = unpack_short(ins)
        self.game_version = unpack_int(ins)
        self.num_plugin_chunks = unpack_int(ins)

    def write_header(self, out):
        super(_xSEHeader, self).write_header(out)
        _pack(out, '=I', self.format_version)
        _pack(out, '=H', self.se_version)
        _pack(out, '=H', self.se_minor_version)
        _pack(out, '=I', self.game_version)
        _pack(out, '=I', self.num_plugin_chunks)

    def dump_header(self, log, save_masters):
        super(_xSEHeader, self).dump_header(log, save_masters)
        log(_(u'  Format version:   %08X') % self.format_version)
        log(_(u'  %s version:      %u.%u') % (self.savefile_tag,
                                              self.se_version,
                                              self.se_minor_version))
        log(_(u'  Game version:     %08X') % self.game_version)

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

    def dump_header(self, log, save_masters):
        super(_PluggyHeader, self).dump_header(log, save_masters)
        log(_(u'  Pluggy file format version: %08X') %
            self._max_supported_version)

#------------------------------------------------------------------------------
# Chunks
class _AChunk(object):
    _esm_encoding = 'cp1252' # TODO ask!
    __slots__ = ()

    def write_chunk(self, out):
        """
        Writes this chunk to the specified output stream.

        :param out: The output stream to write to.
        """

    # TODO(inf) This is a prime target for refactoring in 308+
    # A lot of it could be auto-calculated
    def chunk_length(self):
        """
        Calculates the length of this chunk, i.e. the length of the data that
        follows after this chunk's header.

        :return: The calculated length.
        """

    # TODO(inf) Drop the ins parameter once refactoring is done
    # We'll have entirely shifted to loading the chunks inside __init__ by then
    def log_chunk(self, log, ins, save_masters, espmMap):
        """
        :param save_masters: the espm masters of the save, used in xSE chunks
        :param espmMap: a dict populated in pluggy chunks
        :type log: bolt.Log
        """

class _xSEChunk(_AChunk):
    _espm_chunk_type = {'SDOM'}
    _fully_decoded = False
    __slots__ = ('chunk_type', 'chunk_version', 'chunk_data')

    def __init__(self, ins, chunk_type):
        self.chunk_type = chunk_type
        self.chunk_version = unpack_int(ins)
        data_len = unpack_int(ins)
        if not self._fully_decoded: # if we haven't fully decoded this record,
                                    # treat it as a binary blob
            self.chunk_data = ins.read(data_len)

    def write_chunk(self, out):
        # Don't forget to reverse signature when writing again
        _pack(out, '=4s', self.chunk_type[::-1])
        _pack(out, '=I', self.chunk_version)
        _pack(out, '=I', self.chunk_length())
        if not self._fully_decoded:
            out.write(self.chunk_data)

    def chunk_length(self):
        # No need to check _fully_decoded, subclasses *must* override this
        return len(self.chunk_data)

    def chunk_map_master(self, master_renames_dict, plugin_chunk):
        # TODO Will need rewriting now that the MODS record is fully decoded
        if self.chunk_type not in self._espm_chunk_type:
            return
        old_chunk_length = len(self.chunk_data)
        with sio(self.chunk_data) as ins:
            num_of_masters = unpack_byte(ins) # this won't change
            with sio() as out:
                _pack(out, 'B', num_of_masters)
                while ins.tell() < len(self.chunk_data):
                    modName = GPath(unpack_str16(ins))
                    modName = master_renames_dict.get(modName, modName)
                    modname_str = encode(modName.s,
                                         firstEncoding=self._esm_encoding)
                    _pack(out, '=H', len(modname_str))
                    out.write(modname_str)
                self.chunk_data = out.getvalue()
        chunk_length = len(self.chunk_data)
        plugin_chunk.plugin_data_size += chunk_length - old_chunk_length # Todo Test

class _xSEChunkARVR(_xSEChunk):
    """An ARVR (Array Variable) record. Only available in OBSE and NVSE. See
    ArrayVar.h in xSE's source code for the specification."""
    _fully_decoded = True
    __slots__ = ('mod_index', 'array_id', 'key_type', 'is_packed',
                 'references', 'elements')

    # Warning: Very complex definition coming up
    def __init__(self, ins, chunk_type):
        super(_xSEChunkARVR, self).__init__(ins, chunk_type)
        self.mod_index = unpack_byte(ins)
        self.array_id = unpack_int(ins)
        self.key_type = unpack_byte(ins)
        self.is_packed = unpack_byte(ins)
        if self.chunk_version >= 1:
            num_references = unpack_int(ins)
            self.references = []
            for x in xrange(num_references):
                self.references.append(unpack_byte(ins))
        num_elements = unpack_int(ins)
        self.elements = []
        for x in xrange(num_elements):
            if self.key_type == 1:
                key, = _unpack(ins, '=d', 8)
            elif self.key_type == 3:
                key = ins.read(unpack_short(ins))
            else:
                raise RuntimeError(u'Unknown or unsupported key type %u.' %
                                   self.key_type)
            element_type = unpack_byte(ins)
            if element_type == 1:
                stored_data, = _unpack(ins, '=d', 8)
            elif element_type == 2:
                stored_data = unpack_int(ins)
            elif element_type == 3:
                data_len = unpack_short(ins)
                stored_data = ins.read(data_len)
            elif element_type == 4:
                stored_data = unpack_int(ins)
            else:
                raise RuntimeError(u'Unknown or unsupported element type %u.' %
                                   element_type)
            self.elements.append((key, element_type, stored_data))

    def write_chunk(self, out):
        super(_xSEChunkARVR, self).write_chunk(out)
        _pack(out, '=B', self.mod_index)
        _pack(out, '=I', self.array_id)
        _pack(out, '=B', self.key_type)
        _pack(out, '=B', self.is_packed)
        if self.chunk_version >= 1:
            _pack(out, '=I', len(self.references))
            for reference in self.references:
                _pack(out, '=B', reference)
        _pack(out, '=I', len(self.elements))
        for element in self.elements:
            key, element_type, stored_data = element[0], element[1], element[2]
            if self.key_type == 1:
                _pack(out, '=d', key)
            elif self.key_type == 3:
                _pack(out, '=H', key)
            else:
                raise RuntimeError(u'Unknown or unsupported key type %u.' %
                                   self.key_type)
            _pack(out, '=B', element_type)
            if element_type == 1:
                _pack(out, '=d', stored_data)
            elif element_type == 2:
                _pack(out, '=I', stored_data)
            elif element_type == 3:
                _pack(out, '=H', len(stored_data))
                out.write(stored_data)
            elif element_type == 4:
                _pack(out, '=I', stored_data)
            else:
                raise RuntimeError(u'Unknown or unsupported element type %u.' %
                                   element_type)

    def chunk_length(self):
        # The ones that are always there (3*B, 2*I)
        total_len = 11
        if self.chunk_version >= 1:
            # Every reference is a byte
            total_len += 4 + len(self.references)
        # Every element has a byte, and the type is per chunk, not per element
        element_static_len = 1 + (8 if self.key_type == 1 else 2)
        total_len += element_static_len * len(self.elements)
        # The final part varies per element, so we'll have to run through
        for element in self.elements:
            element_type = element[1]
            if element_type == 1:
                total_len += 8
            elif element_type == 2:
                total_len += 4
            elif element_type == 3:
                total_len += 4 + len(element[2])
            elif element_type == 4:
                total_len += 4
        return total_len

    def log_chunk(self, log, ins, save_masters, espmMap):
        if self.mod_index == 255:
            log(_(u'    Mod :  %02X (Save File)') % self.mod_index)
        else:
            log(_(u'    Mod :  %02X (%s)') % (
                self.mod_index, save_masters[self.mod_index].s))
        log(_(u'    ID  :  %u') % self.array_id)
        if self.key_type == 1: #Numeric
            if self.is_packed:
                log(_(u'    Type:  Array'))
            else:
                log(_(u'    Type:  Map'))
        elif self.key_type == 3:
            log(_(u'    Type:  StringMap'))
        else:
            log(_(u'    Type:  Unknown'))
        if self.chunk_version >= 1:
            log(u'    Refs:')
            for refModID in self.references:
                if refModID == 255:
                    log(_(u'      %02X (Save File)') % refModID)
                else:
                    log(u'      %02X (%s)' % (refModID,
                                              save_masters[refModID].s))
        log(_(u'    Size:  %u') % len(self.elements))
        for element in self.elements:
            key, dataType, stored_data = element[0], element[1], element[2]
            if self.key_type == 1:
                keyStr = u'%f' % key
            elif self.key_type == 3:
                keyStr = decode(key)
            else:
                keyStr = u'BAD'
            dataStr = u'UNKNOWN'
            if dataType == 1:
                dataStr = u'%f' % stored_data
            elif dataType == 2:
                dataStr = u'%08X' % stored_data
            elif dataType == 3:
                dataStr = decode(stored_data)
            elif dataType == 4:
                dataStr = u'%u' % stored_data
            log(u'    [%s]:%s = %s' % (keyStr, (
                u'BAD', u'NUM', u'REF', u'STR', u'ARR')[dataType], dataStr))

class _xSEChunkMODS(_xSEChunk, _Remappable):
    """A MODS (Mod Files) record. Available for all script extenders. See
    Core_Serialization.cpp or InternalSerialization.cpp for its creation (no
    specification available)."""
    _fully_decoded = True
    __slots__ = ('mod_names',)

    def __init__(self, ins, chunk_type):
        super(_xSEChunkMODS, self).__init__(ins, chunk_type)
        mod_count = unpack_byte(ins)
        self.mod_names = []
        for x in xrange(mod_count):
            name_len = unpack_short(ins)
            self.mod_names.append(ins.read(name_len))

    def write_chunk(self, out):
        super(_xSEChunkMODS, self).write_chunk(out)
        _pack(out, '=B', len(self.mod_names))
        for mod_name in self.mod_names:
            _pack(out, '=H', len(mod_name))
            out.write(mod_name)

    def chunk_length(self):
        # One byte for the count, a short per mod name (for string length)
        total_len = 1 + 2 * len(self.mod_names)
        for mod_name in self.mod_names:
            total_len += len(mod_name)
        return total_len

    def log_chunk(self, log, ins, save_masters, espmMap):
        log(_(u'    %u loaded mods:') % len(self.mod_names))
        for mod_name in self.mod_names:
            log(_(u'     - %s') % mod_name)

    def remap_plugins(self, plugin_renames):
        self.mod_names = [plugin_renames.get(x, x) for x in self.mod_names]

class _xSEChunkSTVR(_xSEChunk):
    """An STVR (String Variable) record. Only available in OBSE and NVSE. See
    StringVar.h in xSE's source code for the specification."""
    _fully_decoded = True
    __slots__ = ('mod_index', 'string_id', 'string_data')

    def __init__(self, ins, chunk_type):
        super(_xSEChunkSTVR, self).__init__(ins, chunk_type)
        self.mod_index = unpack_byte(ins)
        self.string_id = unpack_int(ins)
        string_len = unpack_short(ins)
        self.string_data = ins.read(string_len)

    def write_chunk(self, out):
        super(_xSEChunkSTVR, self).write_chunk(out)
        _pack(out, '=B', self.mod_index)
        _pack(out, '=I', self.string_id)
        _pack(out, '=H', len(self.string_data))
        out.write(self.string_data)

    def chunk_length(self):
        return 7 + len(self.string_data)

    def log_chunk(self, log, ins, save_masters, espmMap):
        log(u'    ' + _(u'Mod :') + u'  %02X (%s)' % (
            self.mod_index, save_masters[self.mod_index].s))
        log(u'    ' + _(u'ID  :') + u'  %u' % self.string_id)
        log(u'    ' + _(u'Data:') + u'  %s' % self.string_data)

# TODO(inf) What about pluggy chunks inside xSE cosaves?
class _xSEPluggyChunk(_xSEChunk):
    def log_chunk(self, log, ins, save_masters, espMap):
        chunkTypeNum, = struct_unpack('=I', self.chunk_type)
        if chunkTypeNum == 1:
            #--Pluggy TypeESP
            log(_(u'    Pluggy ESPs'))
            log(_(u'    EID   ID    Name'))
            while ins.tell() < len(self.chunk_data):
                if self.chunk_version == 2:
                    espId, modId, = _unpack(ins, '=BB', 2)
                    log(u'    %02X    %02X' % (espId, modId))
                    espMap[modId] = espId
                else:  #elif self.chunk_version == 1:
                    espId, modId, modNameLen, = _unpack(ins, '=BBI', 6)
                    modName = ins.read(modNameLen)
                    log(u'    %02X    %02X    %s' % (espId, modId, modName))
                    espMap[modId] = modName  # was [espId]
        elif chunkTypeNum == 2:
            #--Pluggy TypeSTR
            log(_(u'    Pluggy String'))
            strId, modId, strFlags, = _unpack(ins, '=IBB', 6)
            strData = ins.read(len(self.chunk_data) - ins.tell())
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
            while ins.tell() < len(self.chunk_data):
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
            refName = ins.read(len(self.chunk_data) - ins.tell())
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
            hudFileName = decode(ins.read(len(self.chunk_data) - ins.tell()))
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
            hudText = decode(ins.read(len(self.chunk_data) - ins.tell()))
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
        chunkTypeNum, = struct_unpack('=I', self.chunk_type)
        if chunkTypeNum != 1:
            return # TODO confirm this is the espm chunk for Pluggy
                   # It is not. 0 is, according to the downloadable save file
                   # documentation.
        with sio(self.chunk_data) as ins:
            with sio() as out:
                while ins.tell() < len(self.chunk_data):
                    espId, modId, modNameLen, = _unpack(ins, '=BBI', 6)
                    modName = GPath(ins.read(modNameLen))
                    modName = master_renames_dict.get(modName, modName)
                    _pack(out, '=BBI', espId, modId, len(modName.s))
                    out.write(encode(modName.cs, ##: why LowerCase ??
                                     firstEncoding=self._esm_encoding))
                self.chunk_data = out.getvalue()
        old_chunk_length = self.chunk_length
        self.chunk_length = len(self.chunk_data)
        plugin_chunk.plugin_data_size += self.chunk_length - old_chunk_length # Todo Test

class _xSEPluginChunk(_AChunk):
    """A single xSE chunk, composed of _xSEChunk (and potentially
    _xSEPluggyChunk) objects."""
    _xse_signature = 0x1400 # signature (aka opcodeBase) of xSE plugin itself
    _pluggy_signature = None # signature (aka opcodeBase) of Pluggy plugin
    __slots__ = ('plugin_signature', 'chunks')

    def __init__(self, ins):
        self.plugin_signature = unpack_4s(ins)[::-1] # aka opcodeBase on pre
                                                     # papyrus
        num_chunks = unpack_int(ins)
        unpack_int(ins) # discard the size, we'll generate it when writing
        self.chunks = []
        for x in xrange(num_chunks):
            ch_class, ch_type = self._get_chunk_type(ins,
                                                     self._xse_signature,
                                                     self._pluggy_signature)
            # If ch_type is None, that means we don't have to pass it on
            if ch_type:
                self.chunks.append(ch_class(ins, ch_type))
            else:
                self.chunks.append(ch_class(ins))

    def write_chunk(self, out):
        # Don't forget to reverse signature when writing again
        _pack(out, '=4s', self.plugin_signature[::-1])
        _pack(out, '=I', len(self.chunks))
        _pack(out, '=I', self.chunk_length())
        for chunk in self.chunks:
            chunk.write_chunk(out)

    def chunk_length(self):
        # Every chunk header has a string of length 4 (type) and two integers
        # (version and length)
        total_len = 12 * len(self.chunks)
        for chunk in self.chunks:
            total_len += chunk.chunk_length()
        return total_len

    def _get_chunk_type(self, ins, xse_signature, pluggy_signature):
        # The chunk type strings are reversed in the cosaves
        chunk_type = unpack_4s(ins)[::-1]
        chunk_class = _xSEChunk
        if chunk_type == 'ARVR':
            chunk_class = _xSEChunkARVR
        elif chunk_type == 'MODS':
            chunk_class = _xSEChunkMODS
        elif chunk_type == 'STVR':
            chunk_class = _xSEChunkSTVR
        return chunk_class, chunk_type

class _PluggyChunk(_AChunk):
    """A single pluggy chunk, of the type that occurs in .pluggy files."""
    __slots__ = ('record_type',)

    def __init__(self, ins):
        self.record_type = unpack_byte(ins)

#------------------------------------------------------------------------------
# Files
class _ACosave(object):
    """The abstract base class for all cosave files."""
    chunk_type = _AChunk
    header_type = _AHeader
    __slots__ = ('cosave_path', 'cosave_header', 'cosave_chunks')

    def __init__(self, cosave_path):
        self.cosave_path = cosave_path
        with cosave_path.open('rb') as ins:
            self.cosave_header = self.header_type(ins, cosave_path)
            self.cosave_chunks = self.load_chunks(ins)

    def load_chunks(self, ins):
        pass

    def write_cosave(self, out_path):
        """
        Writes this cosave to the specified path. Any changes that have been
        done to the cosave in-memory will be written out by this.

        :param out_path: The path to write to.
        """

    def write_cosave_safe(self, out_path=""):
        """
        Writes out any in-memory changes that have been made to this cosave to
        the specified path, first moving it to a temporary location to avoid
        overwriting the original file if something goes wrong.

        :param out_path: The path to write to. If empty or None, this cosave's
                         own path is used instead.
        """
        out_path = out_path or self.cosave_path
        self.write_cosave(out_path.temp)
        out_path.untemp()

    def dump_cosave(self, log, save_masters):
        """
        Dumps information from this cosave into the specified log.

        :param log: A bolt.Log instance to write to.
        :param save_masters: A list of the masters of the save file that this
                             cosave belongs to.
        """

class xSECosave(_ACosave):
    """Represents an xSE cosave, with a .**se extension."""
    chunk_type = _xSEPluginChunk
    header_type = _xSEHeader
    __slots__ = ()

    def load_chunks(self, ins):
        loaded_chunks = []
        for x in xrange(self.cosave_header.num_plugins):
            loaded_chunks.append(self.chunk_type(ins))
        return loaded_chunks

    def map_masters(self, master_renames_dict):
        for plugin_chunk in self.cosave_chunks:
            for chunk in plugin_chunk.plugin_chunks: # TODO avoid scanning all chunks
                chunk.chunk_map_master(master_renames_dict, plugin_chunk)

    def write_cosave(self, out_path):
        mtime = self.cosave_path.mtime # must exist !
        with sio() as buff:
            # We have to update the number of chunks in the header here, since
            # that can't be done automatically
            my_header = self.cosave_header # type: _xSEHeader
            my_header.num_plugin_chunks = len(self.cosave_chunks)
            my_header.write_header(buff)
            for plugin_ch in self.cosave_chunks: # type: _xSEPluginChunk
                plugin_ch.write_chunk(buff)
            text = buff.getvalue()
        with out_path.open('wb') as out:
            out.write(text)
        out_path.mtime = mtime

    def dump_cosave(self, log, save_masters):
        self.cosave_header.dump_header(log, save_masters)
        #--Plugins
        for plugin_ch in self.cosave_chunks: # type: _xSEPluginChunk
            plugin_sig = plugin_ch.plugin_signature
            log.setHeader(_(u'Plugin opcode=%08X chunkNum=%u') % (
                plugin_sig, len(plugin_ch.chunks),))
            log(u'=' * 80)
            log(_(u'  Type  Ver   Size'))
            log(u'-' * 80)
            espMap = {}
            for ch in plugin_ch.chunks: # type: _xSEChunk
                chunkTypeNum, = struct_unpack('=I', ch.chunk_type)
                if ch.chunk_type[0] >= ' ' and ch.chunk_type[3] >= ' ': # HUH ?
                    log(u'  %4s  %-4u  %08X' % (
                        ch.chunk_type, ch.chunk_version, ch.chunk_length()))
                else:
                    log(u'  %04X  %-4u  %08X' % (
                        chunkTypeNum, ch.chunk_version, ch.chunk_length()))
                with sio(ch.chunk_data) as ins:
                    ch.log_chunk(log, ins, save_masters, espMap)

class PluggyCosave(_ACosave):
    """Represents a Pluggy cosave, with a .pluggy extension."""
    chunk_type = _PluggyChunk
    header_type = _PluggyHeader

    def __init__(self, cosave_path):
        super(PluggyCosave, self).__init__(cosave_path)
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

# Factory
def get_cosave_type(game_fsName):
    """:rtype: type"""
    if game_fsName == u'Oblivion':
        _xSEHeader.savefile_tag = 'OBSE'
        _xSEPluginChunk._pluggy_signature = 0x2330
    elif game_fsName == u'Skyrim':
        _xSEHeader.savefile_tag = 'SKSE'
        _xSEPluginChunk._xse_signature = 0x0
    elif game_fsName == u'Skyrim Special Edition':
        _xSEHeader.savefile_tag = 'SKSE'
        _xSEPluginChunk._xse_signature = 0x0
        _xSEChunk._espm_chunk_type = {'SDOM', 'DOML'}
    elif game_fsName == u'Fallout4':
        _xSEHeader.savefile_tag = 'F4SE'
        _xSEPluginChunk._xse_signature = 0x0
        _xSEChunk._espm_chunk_type = {'SDOM', 'DOML'}
    elif game_fsName == u'Fallout3':
        _xSEHeader.savefile_tag = 'FOSE'
    elif game_fsName == u'FalloutNV':
        _xSEHeader.savefile_tag = 'NVSE'
    return xSECosave
