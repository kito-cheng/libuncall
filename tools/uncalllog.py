# -*- Mode: python; tab-width: 4; indent-tab-mode: nil; py-indent-offset: 4 -*-
from elftools.elf.elffile import ELFFile
import re, bisect
import gc


reo_mapsline = re.compile('([0-9a-f]+)-([0-9-a-f]+) ..x. ([0-9a-f]+) ([0-9:]+) ([0-9]+) *([^ ]+)')

class maps(object):
    def __init__(self):
        super(maps, self).__init__()
        self._maps = []
        pass
    
    def load(self, lines):
        for line in lines:
            self.parse_line(line)
            pass
        self.sort_maps()
        pass
    
    def parse_line(self, line):
        mo = reo_mapsline.match(line)
        if not mo:
            return
        item = (int(mo.group(1), 16),
                int(mo.group(2), 16),
                mo.group(6))
        self._maps.append(item)
        pass

    def sort_maps(self):
        self._maps.sort(key=lambda x: x[0])
        pass

    def lookup_address(self, address):
        for start, stop, filename in self._maps:
            if address >= start and address < stop:
                return (start, stop, filename)
            pass
        pass

    def lookup_address_rel(self, address):
        value = self.lookup_address(address)
        if value is not None:
            start, stop, filename = value
            return address - start, filename
        pass
    pass


class flows(object):
    def __init__(self):
        super(flows, self).__init__()
        self._flows = []
        pass

    def load(self, lines):
        for line in lines:
            self.parse_line(line)
            pass
        pass

    def parse_line(self, line):
        if not line:
            return

        frames = [int(ip, 16) for ip in line.split(' ')]
        self._flows.append(frames)
        pass

    def __getitem__(self, idx):
        return self._flows[idx]

    def __len__(self):
        return len(self._flows)
    pass


class uncall_log(object):
    def __init__(self):
        super(uncall_log, self).__init__()
        self.maps = maps()
        self.flows = flows()
        pass
    
    def load(self, filename):
        fo = file(filename, 'r')
        txt = fo.read()
        lines = txt.split('\n')
        maps_idx = lines.index('MAPS:')
        flows_idx = lines.index('FLOWS:')

        self.maps.load(lines[maps_idx + 1: flows_idx])
        self.flows.load(lines[flows_idx + 1:])
        pass
    pass


_interested_IDE_attrs = [
    'DW_AT_MIPS_linkage_name',
    'DW_AT_name',
    'DW_AT_low_pc',
    'DW_AT_high_pc',
    'DW_AT_specification',
    'DW_AT_ranges']

def DIE_values(DIE):
    values = [(name, DIE.attributes[name].value)
              for name in _interested_IDE_attrs
              if DIE.attributes.has_key(name)]
    values.append(('offset', DIE.offset))
    return dict(values)

def filter_CU_DIEs(CU):
    try:
        return CU.DIEs_filtered_cache
    except:
        DIEs = [DIE_values(DIE) for DIE in CU.iter_DIEs()
                if DIE.tag == 'DW_TAG_subprogram']
        CU.DIEs_filtered_cache = DIEs
        CU.clear_DIEs()
        gc.collect()
        pass
    return CU.DIEs_filtered_cache


def print_flows_symbols(log):
    elfs = {}
    result_cache = {}
    
    for i in range(len(log.flows)):
        print 'FLOW:'
        flow = log.flows[i]
        for addr in flow:
            if addr in result_cache:
                print '%s:%s:%s' % result_cache[addr]
                continue
            
            value = log.maps.lookup_address_rel(addr)
            if value is None:
                print '?:?:0x%x' % (addr)
                continue
            rel, so = value
            try:
                elf = elfs[so]
            except:
                fo = file(so, 'rb')
                elf = ELFFile(fo, bytesio=False)
                if not elf.has_dwarf_info():
                    print '%s:?:0x%x(rel:0x%x)' % (so, addr, rel)
                    continue
                    # raise '%s: no dwarf information!' % so
                elfs[so] = elf
                elf.cache_dwarf = elf.get_dwarf_info()
                pass

            if elf['e_type'] == 'ET_EXEC':
                laddr = addr - 1      # for x86, IP is at next opcode.
            else:
                laddr = rel - 1       # for x86, IP is at next opcode.
                pass
            
            dwarf = elf.cache_dwarf
            CU = _CU_finder.addr_to_CU(dwarf, laddr)
            if CU is None:
                print '%s:?:0x%x(rel:0x%x)' % (so, addr, rel)
                continue
            
            func_name = decode_func_name(CU, laddr)
            if func_name:
                func_name = func_name + '()'
            else:
                func_name = '0x%x(rel:0x%x)' % (addr, rel)
                pass
            try:
                filename, line = decode_file_line(CU, laddr)
            except:
                filename, line = so, '?'
                pass
            print '%s:%s:%s' % (filename, line, func_name)
            
            result_cache[addr] = (filename, line, func_name)
            pass
        print
        pass
    pass


#
# C++ (de)mangling tool according C++ ABI.
#
# Only very limited features are implemented for now.  Some one may be
# instered to improve it being more completed.
#
class cxx_mangler(object):
    @staticmethod
    def _demangle_cxx_nested(name, walk_pos):
        parts = []
        while walk_pos < len(name) and str.isdigit(name[walk_pos]):
            value = cxx_mangler._demangle_cxx_part(name, walk_pos)
            walk_pos, part = value
            parts.append(part)
            pass
        
        if not parts or name[walk_pos] != 'E':
            raise SyntaxError, ('%d: invalid foramt!' % walk_pos)
    
        return '::'.join(parts)

    @staticmethod
    def _demangle_cxx_part(name, walk_pos):
        psz_start = walk_pos
        while str.isdigit(name[walk_pos]):
            walk_pos = walk_pos + 1
            pass
        if psz_start == walk_pos:
            raise SyntaxError, ('%d: invalid format!' % psz_start)
        psz = int(name[psz_start : walk_pos])
        if psz <= 0:
            raise SyntaxError, ('%d: invalid format!' % psz_start)
        part = name[walk_pos : walk_pos + psz]
        walk_pos = walk_pos + psz
        return walk_pos, part

    @staticmethod
    def _demangle_cxx(name):
        if name[:2] != '_Z':
            return name
        if name[2] == 'N':
            part = cxx_mangler._demangle_cxx_nested(name, 3)
        else:
            walk_pos, part = cxx_mangler._demangle_cxx_part(name, 2)
            pass
        return part

    @staticmethod
    def demangle(name):
        try:
            return cxx_mangler._demangle_cxx(name)
        except:
            # Too complicate?! Template?! Give up!
            return name
        pass
    pass


def get_name(DIE):
    if DIE.has_key('DW_AT_MIPS_linkage_name'):
        name = DIE['DW_AT_MIPS_linkage_name']
        return cxx_mangler.demangle(name)
    return DIE['DW_AT_name']

def find_spec_name(CU, spec_off):
    for DIE in filter_CU_DIEs(CU):
        if DIE['offset'] == spec_off:
            try:
                return get_name(DIE)
            except KeyError:
                pass
            pass
        pass
    pass

def decode_func_name_CU(CU, addr):
    for DIE in filter_CU_DIEs(CU):
        try:
            lowpc = DIE['DW_AT_low_pc']
            hipc = DIE['DW_AT_high_pc']
            if lowpc <= addr <= hipc:
                try:
                    return get_name(DIE)
                except KeyError:
                    spec_off = DIE['DW_AT_specification']
                    spec_off = spec_off + CU.cu_offset
                    return find_spec_name(CU, spec_off)
                pass
            pass
        except KeyError:
            pass
        pass
    pass


class _CU_finder(object):
    @staticmethod
    def _CU_range_list(CU):
        range_lists = CU.dwarfinfo.range_lists()
        
        top_DIE = CU.get_top_DIE()
        try:
            range_offset = top_DIE.attributes['DW_AT_ranges'].value
        except KeyError:
            return []
        range_list = range_lists.get_range_list_at_offset(range_offset)
        range_pairs = [(range.begin_offset, range.end_offset)
                       for range in  range_list]
        return range_pairs
    
    @staticmethod
    def _sorted_CU_map(dwarf):
        if hasattr(dwarf, 'sorted_CU_map'):
            return (dwarf.sorted_CU_map,
                    dwarf.sorted_CU_map_low,
                    dwarf.sorted_CU_map_high_before)
        
        CU_map = [(low, high, CU)
                  for CU in dwarf.iter_CUs()
                  for low, high in _CU_finder._CU_range_list(CU)]
        CU_map.sort(key=lambda x: x[0])   # This is a stable sorting.
        CU_map_low = [low for low, high, CU in CU_map]
        
        CU_map_high_before = [high for low, high, CU in CU_map]
        before = 0
        for i in range(len(CU_map_high_before)):
            new_high_before = max(before, CU_map_high_before[i])
            CU_map_high_before[i] = before
            before = new_high_before
            pass
        
        dwarf.sorted_CU_map = CU_map
        dwarf.sorted_CU_map_low = CU_map_low
        dwarf.sorted_CU_map_high_before = CU_map_high_before
        return CU_map, CU_map_low, CU_map_high_before

    @staticmethod
    def _first_matched(dwarf, addr):
        sorted_map, sorted_map_low, sorted_map_high_before = \
          _CU_finder._sorted_CU_map(dwarf)
        closest_idx = bisect.bisect_right(sorted_map_low, addr)
        #
        # Since all low addresses before this one is always lower than
        # this one, and the most the high address before thhis one is
        # bigger than the value of addr, then there must be some one
        # earlier before covering the value of addr.
        #
        while addr < sorted_map_high_before[closest_idx]:
            closest_idx = closest_idx - 1
            pass
        #
        # This is the index of the first range in the list that cover
        # the value of addr if there is.  It promises to match the
        # first CU since list.sort() of Python is stable.
        #
        return closest_idx

    @staticmethod
    def addr_to_CU(dwarf, addr):
        sorted_map, sorted_map_low, sorted_map_high_before = \
          _CU_finder._sorted_CU_map(dwarf)
        closest_idx = _CU_finder._first_matched(dwarf, addr)
        low, high, candidate_CU = sorted_map[closest_idx]
        CU = (low <= addr < high) and candidate_CU or None
        return CU
    pass


def decode_func_name(CU, addr):
    if CU is not None:
        return decode_func_name_CU(CU, addr)
    return


def decode_file_line(CU, addr):
    dwarf = CU.dwarfinfo
    
    try:
        lineprog = CU.lineprog_cache
    except:
        lineprog = dwarf.line_program_for_CU(CU)
        CU.lineprog_cache = lineprog
        pass
    
    prevstate = None
    for entry in lineprog.get_entries():
        if entry.state is None or entry.state.end_sequence:
            continue
        if prevstate and prevstate.address <= addr < entry.state.address:
            filename = lineprog['file_entry'][prevstate.file - 1].name
            line = prevstate.line
            return filename, line
        prevstate = entry.state
        pass
    pass


if __name__ == '__main__':
    import sys, pprint
    filename = sys.argv[1]
    log = uncall_log()
    log.load(filename)

    print_flows_symbols(log)
    pass
