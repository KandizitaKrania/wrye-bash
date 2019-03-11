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
import string
from ..bolt import sio, GPath, decode, encode, unpack_string, unpack_int, \
    unpack_short, unpack_4s, unpack_byte, unpack_str16, struct_pack, \
    struct_unpack, deprint, unpack_float, unpack_double, unpack_int_signed
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

class _Dumpable(object):
    """Mixin for objects inside cosaves that can be dumped to a log."""
    def dump_to_log(self, log, save_masters):
        """
        Dumps information from this object into the specified log.

        :param log: A bolt.Log instance to write to.
        :param save_masters: A list of the masters of the save file that this
                             object's cosave belongs to.
        """
        raise AbstractError()

#------------------------------------------------------------------------------
# Headers
class _AHeader(_Dumpable):
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
            raise FileError(cosave_path.tail, u'Header tag wrong: got %r, but '
                                              u'expected %r' %
                            (actual_tag, self.savefile_tag))

    def write_header(self, out):
        """
        Writes this header to the specified output stream. The base method just
        writes the save file tag.

        :param out: The output stream to write to.
        """
        out.write(self.savefile_tag)

    def dump_to_log(self, log, save_masters):
        log.setHeader(_(u'%s Header') % self.savefile_tag)
        log(u'=' * 40)

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

    def dump_to_log(self, log, save_masters):
        super(_xSEHeader, self).dump_to_log(log, save_masters)
        log(_(u'  Format version:   0x%08X') % self.format_version)
        log(_(u'  %s version:      %u.%u') % (self.savefile_tag,
                                              self.se_version,
                                              self.se_minor_version))
        log(_(u'  Game version:     0x%08X') % self.game_version)

class _PluggyHeader(_AHeader):
    """Header for pluggy cosaves. Just checks save file tag and version."""
    savefile_tag = 'PluggySave'
    _max_supported_version = 0x01050000
    _min_supported_version = 0x01020000
    __slots__ = ()

    def __init__(self, ins, cosave_path):
        super(_PluggyHeader, self).__init__(ins, cosave_path)
        version = unpack_int(ins)
        if version > self._max_supported_version:
            raise FileError(cosave_path.tail, u'Version of pluggy save file'
                                              u'format is too new - only'
                                              u'versions up to 1.6.0000 are'
                                              u'supported.')
        elif version < self._min_supported_version:
            raise FileError(cosave_path.tail, u'Version of pluggy save file'
                                              u'format is too old - only'
                                              u'verions >= 1.2.0000 are'
                                              u'supported.')

    def write_header(self, out):
        super(_PluggyHeader, self).write_header(out)
        _pack(out, '=I', self._max_supported_version)

    def dump_to_log(self, log, save_masters):
        super(_PluggyHeader, self).dump_to_log(log, save_masters)
        log(_(u'  Pluggy file format version: 0x%08X') %
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


    # TODO(inf) This is a prime target for refactoring in 308+
    # A lot of it could be auto-calculated
    def chunk_length(self):
        """
        Calculates the length of this chunk, i.e. the length of the data that
        follows after this chunk's header.

        :return: The calculated length.
        """
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

class _xSEModListChunk(_xSEChunk, _Dumpable, _Remappable):
    """An abstract class for chunks that contain a list of mods (e.g. MODS or
    LIMD) """
    __slots__ = ('mod_names',)

    def __init__(self, ins, chunk_type):
        super(_xSEModListChunk, self).__init__(ins, chunk_type)
        self.mod_names = []

    def read_mod_names(self, ins, mod_count):
        """
        Reads a list of mod names with length mod_count from the specified
        input stream. The result is saved in the mod_names variable.

        :param ins: The input stream to read from.
        :param mod_count: The number of mod names to read.
        """
        for x in xrange(mod_count):
            self.mod_names.append(ins.read(unpack_short(ins)))

    def write_mod_names(self, out):
        """
        Writes the saved list of mod names to the specified output stream.

        :param out: The output stream to write to.
        """
        for mod_name in self.mod_names:
            _pack(out, '=H', len(mod_name))
            out.write(mod_name)

    def chunk_length(self):
        # 2 bytes per mod name (for the length)
        total_len = len(self.mod_names) * 2
        for mod_name in self.mod_names:
            total_len += len(mod_name)
        return total_len

    def dump_to_log(self, log, save_masters):
        for mod_name in self.mod_names:
            log(_(u'    - %s') % mod_name)

    def remap_plugins(self, plugin_renames):
        self.mod_names = [plugin_renames.get(x, x) for x in self.mod_names]

class _xSEChunkARVR(_xSEChunk, _Dumpable):
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
                key = unpack_double(ins)
            elif self.key_type == 3:
                key = ins.read(unpack_short(ins))
            else:
                raise RuntimeError(u'Unknown or unsupported key type %u.' %
                                   self.key_type)
            element_type = unpack_byte(ins)
            if element_type == 1:
                stored_data, = unpack_double(ins)
            elif element_type == 2:
                stored_data = unpack_int(ins)
            elif element_type == 3:
                stored_data = ins.read(unpack_short(ins))
            elif element_type == 4:
                stored_data = unpack_int(ins)
            else:
                raise RuntimeError(u'Unknown or unsupported element type %u.' %
                                   element_type)
            self.elements.append([key, element_type, stored_data])

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
            key = element[0]
            if self.key_type == 1:
                _pack(out, '=d', key)
            elif self.key_type == 3:
                _pack(out, '=H', key)
            else:
                raise RuntimeError(u'Unknown or unsupported key type %u.' %
                                   self.key_type)
            element_type = element[1]
            _pack(out, '=B', element_type)
            stored_data = element[2]
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

    def dump_to_log(self, log, save_masters):
        if self.mod_index == 255:
            log(_(u'   Mod :  %02X (Save File)') % self.mod_index)
        else:
            log(_(u'   Mod :  %02X (%s)') % (
                self.mod_index, save_masters[self.mod_index].s))
        log(_(u'   ID  :  %u') % self.array_id)
        if self.key_type == 1: #Numeric
            if self.is_packed:
                log(_(u'   Type:  Array'))
            else:
                log(_(u'   Type:  Map'))
        elif self.key_type == 3:
            log(_(u'   Type:  StringMap'))
        else:
            log(_(u'   Type:  Unknown'))
        if self.chunk_version >= 1:
            log(u'   Refs:')
            for refModID in self.references:
                if refModID == 255:
                    log(_(u'    - %02X (Save File)') % refModID)
                else:
                    log(u'    - %02X (%s)' % (refModID,
                                              save_masters[refModID].s))
        log(_(u'   Size:  %u') % len(self.elements))
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
                dataStr = u'0x%08X' % stored_data
            elif dataType == 3:
                dataStr = decode(stored_data)
            elif dataType == 4:
                dataStr = u'%u' % stored_data
            log(u'    - [%s]:%s = %s' % (keyStr, (
                u'BAD', u'NUM', u'REF', u'STR', u'ARR')[dataType], dataStr))

class _xSEChunkLIMD(_xSEModListChunk):
    """An LIMD (Light Mod Files) chunk. Available for SKSE64 and F4SE. This is
    the new version of the LMOD chunk. In constrast to LMOD, LIMD can store
    more than 255 light mods (up to 65535). See Core_Serialization.cpp or
    InternalSerialization.cpp for its creation (no specification available)."""
    _fully_decoded = True
    __slots__ = ()

    def __init__(self, ins, chunk_type):
        super(_xSEChunkLIMD, self).__init__(ins, chunk_type)
        self.read_mod_names(ins, unpack_short(ins))

    def write_chunk(self, out):
        super(_xSEChunkLIMD, self).write_chunk(out)
        _pack(out, '=H', len(self.mod_names))
        self.write_mod_names(out)

    def chunk_length(self):
        return 2 + super(_xSEChunkLIMD, self).chunk_length()

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u loaded light mods:') % len(self.mod_names))
        super(_xSEChunkLIMD, self).dump_to_log(log, save_masters)

class _xSEChunkLMOD(_xSEModListChunk):
    """An LMOD (Light Mod Files) chunk. Only available in SKSE64 and F4SE. This
    is the legacy version of the LIMD chunk, which is no longer generated by
    newer xSE versions. The difference is that this one only supported up to
    255 light mods, while the games themselves support more than that."""
    _fully_decoded = True
    __slots__ = ()

    def __init__(self, ins, chunk_type):
        super(_xSEChunkLMOD, self).__init__(ins, chunk_type)
        self.read_mod_names(ins, unpack_byte(ins))

    def write_chunk(self, out):
        super(_xSEChunkLMOD, self).write_chunk(out)
        _pack(out, '=B', len(self.mod_names))
        self.write_mod_names(out)

    def chunk_length(self):
        return 1 + super(_xSEChunkLMOD, self).chunk_length()

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u loaded light mods:') % len(self.mod_names))
        super(_xSEChunkLMOD, self).dump_to_log(log, save_masters)

class _xSEChunkMODS(_xSEModListChunk):
    """A MODS (Mod Files) record. Available for all script extenders. See
    Core_Serialization.cpp or InternalSerialization.cpp for its creation (no
    specification available)."""
    _fully_decoded = True
    __slots__ = ()

    def __init__(self, ins, chunk_type):
        super(_xSEChunkMODS, self).__init__(ins, chunk_type)
        self.read_mod_names(ins, unpack_byte(ins))

    def write_chunk(self, out):
        super(_xSEChunkMODS, self).write_chunk(out)
        _pack(out, '=B', len(self.mod_names))
        self.write_mod_names(out)

    def chunk_length(self):
        return 1 + super(_xSEChunkMODS, self).chunk_length()

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u loaded mods:') % len(self.mod_names))
        super(_xSEChunkMODS, self).dump_to_log(log, save_masters)

class _xSEChunkSTVR(_xSEChunk, _Dumpable):
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

    def dump_to_log(self, log, save_masters):
        log(_(u'   Mod : %02X (%s)') % (self.mod_index,
                                        save_masters[self.mod_index].s))
        log(_(u'   ID  : %u') % self.string_id)
        log(_(u'   Data: %s') % self.string_data)

# TODO(inf) What about pluggy chunks inside xSE cosaves?
class _xSEPluggyChunk(_xSEChunk):
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
    __slots__ = ('plugin_signature', 'chunks')

    def __init__(self, ins):
        self.plugin_signature = unpack_int(ins) # aka opcodeBase on pre papyrus
        num_chunks = unpack_int(ins)
        ins.read(4) # discard the size, we'll generate it when writing
        self.chunks = []
        for x in xrange(num_chunks):
            ch_class, ch_type = self._get_chunk_type(ins)
            # If ch_type is None, that means we don't have to pass it on
            if ch_type:
                self.chunks.append(ch_class(ins, ch_type))
            else:
                self.chunks.append(ch_class(ins))

    def write_chunk(self, out):
        # Don't forget to reverse signature when writing again
        _pack(out, '=I', self.plugin_signature)
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

    @staticmethod
    def _get_chunk_type(ins):
        # The chunk type strings are reversed in the cosaves
        # TODO(inf) Use a dict for these
        # TODO(inf) Additionally, post 308 we may want to reorganize these into
        # a records.py-like structure
        chunk_type = unpack_4s(ins)[::-1]
        chunk_class = _xSEChunk
        if chunk_type == 'ARVR':
            chunk_class = _xSEChunkARVR
        elif chunk_type == 'LIMD':
            chunk_class = _xSEChunkLIMD
        elif chunk_type == 'LMOD':
            chunk_class = _xSEChunkLMOD
        elif chunk_type == 'MODS':
            chunk_class = _xSEChunkMODS
        elif chunk_type == 'STVR':
            chunk_class = _xSEChunkSTVR
        return chunk_class, chunk_type

class _PluggyBlock(_AChunk, _Dumpable):
    """A single pluggy record block. This is the pluggy equivalent of xSE
    chunks."""
    __slots__ = ('record_type',)

    def __init__(self, record_type):
        self.record_type = record_type

class _PluggyPluginBlock(_PluggyBlock, _Remappable):
    """The plugin records block of a pluggy cosave. Contains a list of the
    save's masters. This is the only required block, it must be present and is
    always the first block in the cosave."""
    __slots__ = ('plugins',)

    def __init__(self, ins, record_type):
        super(_PluggyPluginBlock, self).__init__(record_type)
        plugin_count = unpack_int(ins)
        self.plugins = []
        for x in xrange(plugin_count):
            pluggy_id = unpack_byte(ins)
            game_id = unpack_byte(ins)
            plugin_name = ins.read(unpack_int(ins))
            self.plugins.append([pluggy_id, game_id, plugin_name])

    def write_chunk(self, out):
        _pack(out, '=I', len(self.plugins))
        for plugin in self.plugins:
            plugin_name = plugin[2]
            _pack(out, '=B', plugin[0])
            _pack(out, '=B', plugin[1])
            _pack(out, '=I', len(plugin_name))
            out.write(plugin_name)

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u loaded mods:') % len(self.plugins))
        log(_(u'   EID   ID    Name'))
        log(u'-' * 40)
        for plugin in self.plugins:
            log(u'    %02X    %02X    %s' % (plugin[0], plugin[1], plugin[2]))

    def remap_plugins(self, plugin_renames):
        for plugin in self.plugins:
            plugin_name = plugin[2]
            plugin[2] = plugin_renames.get(plugin_name, plugin_name)

class _PluggyStringBlock(_PluggyBlock):
    """The string records block of a pluggy cosave. Contains string data from
    plugins that was saved. This is an optional block and, if present, follows
    directly after the plugin block."""
    __slots__ = ('stored_strings',)

    def __init__(self, ins, record_type):
        super(_PluggyStringBlock, self).__init__(record_type)
        string_count = unpack_int(ins)
        self.stored_strings = []
        for x in xrange(string_count):
            string_id = unpack_int(ins)
            plugin_index = unpack_byte(ins)
            string_flags = unpack_byte(ins)
            string_len = unpack_int(ins)
            string_data = ins.read(string_len)
            self.stored_strings.append([string_id, plugin_index, string_flags,
                                        string_data])

    def write_chunk(self, out):
        _pack(out, '=I', len(self.stored_strings))
        for stored_string in self.stored_strings:
            _pack(out, '=I', stored_string[0])
            _pack(out, '=B', stored_string[1])
            _pack(out, '=B', stored_string[2])
            string_data = stored_string[3]
            _pack(out, '=I', len(string_data))
            out.write(string_data)

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u stored strings:') % len(self.stored_strings))
        for stored_string in self.stored_strings:
            log(_(u'    - ID    : %u') % stored_string[0])
            plugin_index = stored_string[1]
            log(_(u'      Owner : %s (%02X)') % (save_masters[plugin_index],
                                                 plugin_index))
            log(_(u'      Flags : %u') % stored_string[2])
            log(_(u'      Data  : %s') % stored_string[3])

class _PluggyArrayBlock(_PluggyBlock):
    """An array records block of a pluggy cosave. Contains an array from a
    plugin that was saved. This is an optional block and, if present, one or
    more of these (one for each saved array) follow directly after the string
    block."""
    __slots__ = ('array_id', 'plugin_index', 'array_flags', 'max_size',
                 'array_entries')

    def __init__(self, ins, record_type):
        super(_PluggyArrayBlock, self).__init__(record_type)
        self.array_id = unpack_int(ins)
        self.plugin_index = unpack_byte(ins)
        self.array_flags = unpack_byte(ins)
        self.max_size = unpack_int(ins)
        self.array_entries = []
        for x in range(unpack_int(ins)):
            entry_index = unpack_int(ins)
            entry_type = unpack_byte(ins)
            if entry_type == 0:
                entry_data = unpack_int_signed(ins)
            elif entry_type == 1:
                entry_data = unpack_int(ins)
            elif entry_type == 2:
                entry_data = unpack_float(ins)
            else:
                raise RuntimeError(u'Unknown or unsupported entry type %u.' %
                                   entry_type)
            self.array_entries.append([entry_index, entry_type, entry_data])

    def write_chunk(self, out):
        _pack(out, '=I', self.array_id)
        _pack(out, '=B', self.plugin_index)
        _pack(out, '=B', self.array_flags)
        _pack(out, '=I', self.max_size)
        _pack(out, '=I', len(self.array_entries))
        for array_entry in self.array_entries:
            _pack(out, '=I', array_entry[0])
            entry_type = array_entry[1]
            _pack(out, '=B', entry_type)
            if entry_type == 0:
                _pack(out, '=i', array_entry[2])
            elif entry_type == 1:
                _pack(out, '=I', array_entry[2])
            elif entry_type == 2:
                _pack(out, '=f', array_entry[2])
            else:
                raise RuntimeError(u'Unknown or unsupported entry type %u.' %
                                   entry_type)

    def dump_to_log(self, log, save_masters):
        log(_(u'   Pluggy Array #%u') % self.array_id)
        log(_(u'    Owner   : %s (%02X)') % (save_masters[self.plugin_index],
                                             self.plugin_index))
        log(_(u'    Flags   : %u') % self.array_flags)
        log(_(u'    Max Size: %u') % self.max_size)
        log(_(u'    Cur Size: %u') % len(self.array_entries))
        log(_(u'    Contents:'))
        for array_entry in self.array_entries:
            entry_type = array_entry[1]
            if entry_type == 0:
                log(u'     %u: %d' % (array_entry[0], array_entry[2]))
            elif entry_type == 1:
                log(u'     %u: 0x%08X' % (array_entry[0], array_entry[2]))
            elif entry_type == 2:
                log(u'     %u: %f' % (array_entry[0], array_entry[2]))

class _PluggyNameBlock(_PluggyBlock):
    """A name records block of a pluggy cosave. Contains one or more names that
    were saved. This is an optional block and, if present, it follows directly
    after the array blocks."""
    __slots__ = ('stored_names',)

    def __init__(self, ins, record_type):
        super(_PluggyNameBlock, self).__init__(record_type)
        name_count = unpack_int(ins)
        self.stored_names = []
        for x in xrange(name_count):
            reference_id = unpack_int(ins)
            name_len = unpack_int(ins)
            name_data = ins.read(name_len)
            self.stored_names.append([reference_id, name_data])

    def write_chunk(self, out):
        _pack(out, '=I', len(self.stored_names))
        for stored_name in self.stored_names:
            _pack(out, '=I', stored_name[0])
            name_data = stored_name[1]
            _pack(out, '=I', len(name_data))
            out.write(name_data)

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u stored names:') % len(self.stored_names))
        for stored_name in self.stored_names:
            log(_(u'    - RefID : 0x%08X') % stored_name[0])
            printable_name = u''
            for c in stored_name[1]:
                # Strip non-printable characters
                ch = c if c in string.printable else ''
                printable_name = printable_name + ch
            log(_(u'      Name  : %s') % decode(printable_name))

class _PluggyScreenInfoBlock(_PluggyBlock):
    """A screen information record block. This is an optional block and, if
    present, follows directly after the name block. Note that this block will
    only ever be present if there is at least one HudS or HudT block."""
    __slots__ = ('screen_width', 'screen_height')

    def __init__(self, ins, record_type):
        super(_PluggyScreenInfoBlock, self).__init__(record_type)
        self.screen_width = unpack_int(ins)
        self.screen_height = unpack_int(ins)

    def write_chunk(self, out):
        _pack(out, '=I', self.screen_width)
        _pack(out, '=I', self.screen_height)

    def dump_to_log(self, log, save_masters):
        log(_(u'   Width : %u') % self.screen_width)
        log(_(u'   Height: %u') % self.screen_height)

class _PluggyHudSBlock(_PluggyBlock):
    """A HUD Screen / Image records block. Contains information related to
    custom HUDs that was saved. This is an optional block and, if present,
    follows directly after the screen info block."""
    __slots__ = ('hud_entries',)

    def __init__(self, ins, record_type):
        super(_PluggyHudSBlock, self).__init__(record_type)
        self.hud_entries = []
        for x in xrange(unpack_int(ins)):
            hud_id = unpack_int(ins)
            plugin_index = unpack_byte(ins)
            hud_flags = unpack_byte(ins)
            root_id = unpack_byte(ins)
            file_name = ins.read(unpack_int(ins))
            show_mode = unpack_byte(ins)
            pos_x = unpack_int(ins)
            pos_y = unpack_int(ins)
            depth = unpack_short(ins)
            scale_x = unpack_int(ins)
            scale_y = unpack_int(ins)
            ins.read(4) # Discard, unused
            alpha = unpack_byte(ins)
            alignment = unpack_byte(ins)
            auto_scale = unpack_byte(ins)
            self.hud_entries.append([hud_id, plugin_index, hud_flags, root_id,
                                     file_name, show_mode, pos_x, pos_y, depth,
                                     scale_x, scale_y, alpha, alignment,
                                     auto_scale])

    def write_chunk(self, out):
        _pack(out, '=I', len(self.hud_entries))
        for hud_entry in self.hud_entries:
            _pack(out, '=I', hud_entry[0])      # hud_id
            _pack(out, '=B', hud_entry[1])      # plugin_index
            _pack(out, '=B', hud_entry[2])      # hud_flags
            _pack(out, '=B', hud_entry[3])      # root_id
            file_name = hud_entry[4]
            _pack(out, '=I', len(file_name))
            out.write(file_name)
            _pack(out, '=B', hud_entry[5])      # show_mode
            _pack(out, '=I', hud_entry[6])      # pos_x
            _pack(out, '=I', hud_entry[7])      # pos_y
            _pack(out, '=H', hud_entry[8])      # depth
            _pack(out, '=I', hud_entry[9])      # scale_x
            _pack(out, '=I', hud_entry[10])     # scale_y
            _pack(out, '=I', 0)                 # unused
            _pack(out, '=B', hud_entry[11])     # alpha
            _pack(out, '=B', hud_entry[12])     # alignment
            _pack(out, '=B', hud_entry[13])     # auto_scale

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u HUD Screen entries:') % len(self.hud_entries))
        for hud_entry in self.hud_entries:
            log(_(u'    - HUD ID    : %u') % hud_entry[0])
            plugin_index = hud_entry[1]
            log(_(u'      Owner     : %s (%02X)') % (
                save_masters[plugin_index], plugin_index))
            log(_(u'      Flags     : %02X') % hud_entry[2])
            log(_(u'      Root ID   : %u') % hud_entry[3])
            log(_(u'      File      : %s') % hud_entry[4])
            log(_(u'      Show Mode : %02X') % hud_entry[5])
            log(_(u'      X Position: %u') % hud_entry[6])
            log(_(u'      Y Position: %u') % hud_entry[7])
            log(_(u'      Depth     : %u') % hud_entry[8])
            log(_(u'      X Scale   : %u') % hud_entry[9])
            log(_(u'      Y Scale   : %u') % hud_entry[10])
            log(_(u'      Alpha     : %02X') % hud_entry[11])
            log(_(u'      Alignment : %02X') % hud_entry[12])
            log(_(u'      Auto-Scale: %02X') % hud_entry[13])

class _PluggyHudTBlock(_PluggyBlock):
    """A HUD Text records block. Contains information related to custom HUDs
    that was saved. This is an optional block and, if present, follows directly
    after the HudS block."""
    __slots__ = ('hud_entries',)

    def __init__(self, ins, record_type):
        super(_PluggyHudTBlock, self).__init__(record_type)
        self.hud_entries = []
        for x in xrange(unpack_int(ins)):
            hud_id = unpack_int(ins)
            plugin_index = unpack_byte(ins)
            hud_flags = unpack_byte(ins)
            show_mode = unpack_byte(ins)
            pos_x = unpack_int(ins)
            pos_y = unpack_int(ins)
            depth = unpack_short(ins)
            scale_x = unpack_int(ins)
            scale_y = unpack_int(ins)
            ins.read(4) # Discard, unused
            alpha = unpack_byte(ins)
            alignment = unpack_byte(ins)
            auto_scale = unpack_byte(ins)
            hud_width = unpack_int(ins)
            hud_height = unpack_int(ins)
            text_format = unpack_byte(ins)
            font_name = ins.read(unpack_int(ins))
            text_data = ins.read(unpack_int(ins))
            font_height = unpack_int(ins)
            font_width = unpack_int(ins)
            font_boldness = unpack_short(ins)
            font_italic = unpack_byte(ins)
            font_red = unpack_byte(ins)
            font_green = unpack_byte(ins)
            font_blue = unpack_byte(ins)
            self.hud_entries.append([hud_id, plugin_index, hud_flags,
                                     show_mode, pos_x, pos_y, depth, scale_x,
                                     scale_y, alpha, alignment, auto_scale,
                                     hud_width, hud_height, text_format,
                                     font_name, text_data, font_height,
                                     font_width, font_boldness, font_italic,
                                     font_red, font_green, font_blue])

    def write_chunk(self, out):
        _pack(out, '=I', len(self.hud_entries))
        for hud_entry in self.hud_entries:
            _pack(out, '=I', hud_entry[0])  # hud_id
            _pack(out, '=B', hud_entry[1])  # plugin_index
            _pack(out, '=B', hud_entry[2])  # hud_flags
            _pack(out, '=B', hud_entry[3])  # show_mode
            _pack(out, '=I', hud_entry[4])  # pos_x
            _pack(out, '=I', hud_entry[5])  # pos_y
            _pack(out, '=H', hud_entry[6])  # depth
            _pack(out, '=I', hud_entry[7])  # scale_x
            _pack(out, '=I', hud_entry[8])  # scale_y
            _pack(out, '=I', 0)             # unused
            _pack(out, '=B', hud_entry[9])  # alpha
            _pack(out, '=B', hud_entry[10]) # alignment
            _pack(out, '=B', hud_entry[11]) # auto_scale
            _pack(out, '=I', hud_entry[12]) # hud_width
            _pack(out, '=I', hud_entry[13]) # hud_height
            _pack(out, '=B', hud_entry[14]) # text_format
            font_name = hud_entry[15]
            _pack(out, '=I', len(font_name))
            out.write(font_name)
            text_data = hud_entry[16]
            _pack(out, '=I', len(text_data))
            out.write(text_data)
            _pack(out, '=I', hud_entry[17]) # font_height
            _pack(out, '=I', hud_entry[18]) # font_width
            _pack(out, '=H', hud_entry[19]) # font_boldness
            _pack(out, '=B', hud_entry[20]) # font_italic
            _pack(out, '=B', hud_entry[21]) # font_red
            _pack(out, '=B', hud_entry[22]) # font_green
            _pack(out, '=B', hud_entry[23]) # font_blue

    def dump_to_log(self, log, save_masters):
        log(_(u'   %u HUD Text entries:') % len(self.hud_entries))
        for hud_entry in self.hud_entries:
            log(_(u'    - HUD ID     : %u') % hud_entry[0])
            plugin_index = hud_entry[1]
            log(_(u'      Owner      : %s (%02X)') % (
                save_masters[plugin_index], plugin_index))
            log(_(u'      Flags      : %02X') % hud_entry[2])
            log(_(u'      Show Mode  : %02X') % hud_entry[3])
            log(_(u'      X Position : %u') % hud_entry[4])
            log(_(u'      Y Position : %u') % hud_entry[5])
            log(_(u'      Depth      : %u') % hud_entry[6])
            log(_(u'      X Scale    : %u') % hud_entry[7])
            log(_(u'      Y Scale    : %u') % hud_entry[8])
            log(_(u'      Alpha      : %02X') % hud_entry[9])
            log(_(u'      Alignment  : %02X') % hud_entry[10])
            log(_(u'      Auto-Scale : %02X') % hud_entry[11])
            log(_(u'      HUD Width  : %u') % hud_entry[12])
            log(_(u'      HUD Height : %u') % hud_entry[13])
            log(_(u'      Text Format: %u') % hud_entry[14])
            log(_(u'      Font Name  : %s') % hud_entry[15])
            log(_(u'      Text Data  : %s') % hud_entry[16])
            log(_(u'      Font Height: %u') % hud_entry[17])
            log(_(u'      Font Width : %u') % hud_entry[18])
            log(_(u'      Boldness   : %u') % hud_entry[19])
            log(_(u'      Italic     : %u') % hud_entry[20])
            log(_(u'      Font Color : (%u, %u, %u)') % (hud_entry[21],
                                                         hud_entry[22],
                                                         hud_entry[23]))

#------------------------------------------------------------------------------
# Files
class _ACosave(_Dumpable):
    """The abstract base class for all cosave files."""
    header_type = _AHeader
    __slots__ = ('cosave_path', 'cosave_header', 'cosave_chunks')

    def __init__(self, cosave_path):
        self.cosave_path = cosave_path
        with cosave_path.open('rb') as ins:
            self.cosave_header = self.header_type(ins, cosave_path)
            self.cosave_chunks = self.read_chunks(ins)

    def read_chunks(self, ins):
        """
        Reads the chunks of this cosave. For xSE cosaves, these are the 'plugin
        chunks'. For pluggy cosaves, these are the 'record blocks'.

        :param ins: The input stream to read from.
        :return: A list of all the chunks of this cosave.
        """
        raise AbstractError()

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

class xSECosave(_ACosave):
    """Represents an xSE cosave, with a .**se extension."""
    header_type = _xSEHeader
    _pluggy_signature = None # signature (aka opcodeBase) of Pluggy plugin
    _xse_signature = 0x1400 # signature (aka opcodeBase) of xSE plugin itself
    __slots__ = ()

    def read_chunks(self, ins):
        read_chunks = []
        my_header = self.cosave_header # type: _xSEHeader
        for x in xrange(my_header.num_plugin_chunks):
            read_chunks.append(_xSEPluginChunk(ins))
        return read_chunks

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

    def dump_to_log(self, log, save_masters):
        self.cosave_header.dump_to_log(log, save_masters)
        for plugin_chunk in self.cosave_chunks: # type: _xSEPluginChunk
            plugin_sig = self._get_plugin_signature(plugin_chunk)
            log.setHeader(_(u'Plugin: %s, Total chunks: %u') % (
                plugin_sig, len(plugin_chunk.chunks)))
            log(u'=' * 40)
            log(_(u'  Type   Version  Size (in bytes)'))
            log(u'-' * 40)
            for chunk in plugin_chunk.chunks: # type: _xSEChunk
                log(u'  %4s  %-4u        %u' % (chunk.chunk_type,
                                                chunk.chunk_version,
                                                chunk.chunk_length()))
                if isinstance(chunk, _Dumpable):
                    chunk.dump_to_log(log, save_masters)

    def _get_plugin_signature(self, plugin_chunk):
        """
        Creates a human-readable version of the specified plugin chunk's
        signature.

        :param plugin_chunk: The plugin chunk whose signature should be
                             processed.
        :return: A human-readable version of the plugin chunk's signature.
        """
        raw_sig = plugin_chunk.plugin_signature
        if raw_sig == self._xse_signature:
            readable_sig = self.cosave_header.savefile_tag
        elif raw_sig == self._pluggy_signature:
            readable_sig = u'Pluggy'
        else:
            # Reverse the result since xSE writes signatures backwards
            # TODO(inf) There has to be a better way to do this
            readable_sig = (self._to_unichr(raw_sig, 0) +
                            self._to_unichr(raw_sig, 8) +
                            self._to_unichr(raw_sig, 16) +
                            self._to_unichr(raw_sig, 24))[::-1]
        return readable_sig + u' (0x%X)' % raw_sig

    @staticmethod
    def _to_unichr(target_int, shift):
        """
        Small helper method for _get_plugin_signature that interprets the
        result of shifting the specified integer by the specified shift amount
        and masking with 0xFF as a unichr. Additionally, if the result of that
        operation is not printable, an empty string is returned instead.

        :param target_int: The integer to shift and mask.
        :param shift: By how much (in bits) to shift.
        :return: The unichr representation of the result, or an empty string.
        """
        temp_char = unichr(target_int >> shift & 0xFF)
        if temp_char not in string.printable:
            temp_char = u''
        return temp_char

class PluggyCosave(_ACosave):
    """Represents a Pluggy cosave, with a .pluggy extension."""
    header_type = _PluggyHeader
    # Used to convert from block type int to block class
    # See pluggy file format specification for how these map
    _block_types = [_PluggyPluginBlock, _PluggyStringBlock, _PluggyArrayBlock,
                    _PluggyNameBlock, _PluggyScreenInfoBlock, _PluggyHudSBlock,
                    _PluggyHudTBlock]
    __slots__ = ()

    def read_chunks(self, ins):
        read_chunks = []
        while True:
            raw_type = ins.read(1)
            if not raw_type: break # EOF
            record_type = struct_unpack('=B', raw_type)[0]
            block_type = self._get_block_type(record_type)
            read_chunks.append(block_type(record_type))
        return read_chunks

    def _get_block_type(self, record_type):
        """
        Returns the matching block type for the specified record type or raises
        an informative error if the record type is not known.

        :param record_type: An integer representing the read record type.
        """
        if record_type < len(self._block_types):
            return self._block_types[record_type]
        else:
            raise FileError(self.cosave_path.tail, u'Unknown pluggy record'
                                                   u'block type %u.' %
                            record_type)

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
                                u'Expected plugins record, but got %u.' % type)
            count, = _unpack(ins, '=I', 4)
            for x in range(count):
                espid,index,modLen = _unpack(ins, '=2BI', 6)
                modName = GPath(decode(ins.read(modLen)))
                self._plugins.append([espid, index, modName])
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
        xSECosave._pluggy_signature = 0x2330
        _xSEHeader.savefile_tag = 'OBSE'
    elif game_fsName == u'Skyrim':
        xSECosave._xse_signature = 0x0
        _xSEHeader.savefile_tag = 'SKSE'
    elif game_fsName == u'Skyrim Special Edition':
        xSECosave._xse_signature = 0x0
        _xSEHeader.savefile_tag = 'SKSE'
        _xSEChunk._espm_chunk_type = {'SDOM', 'DOML'}
    elif game_fsName == u'Fallout4':
        xSECosave._xse_signature = 0x0
        _xSEHeader.savefile_tag = 'F4SE'
        _xSEChunk._espm_chunk_type = {'SDOM', 'DOML'}
    elif game_fsName == u'Fallout3':
        _xSEHeader.savefile_tag = 'FOSE'
    elif game_fsName == u'FalloutNV':
        _xSEHeader.savefile_tag = 'NVSE'
    return xSECosave
