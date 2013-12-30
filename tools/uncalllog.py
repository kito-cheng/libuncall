# -*- Mode: python; tab-width: 4; indent-tab-mode: nil; py-indent-offset: 4 -*-
from elftools.elf.elffile import ELFFile
import re


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
                elf = ELFFile(fo)
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
            func_name = decode_func_name(dwarf, laddr)
            if func_name:
                func_name = func_name + '()'
            else:
                func_name = '0x%x(rel:0x%x)' % (addr, rel)
                pass
            try:
                filename, line = decode_file_line(dwarf, laddr)
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
    if DIE.attributes.has_key('DW_AT_MIPS_linkage_name'):
        name = DIE.attributes['DW_AT_MIPS_linkage_name'].value
        return cxx_mangler.demangle(name)
    return DIE.attributes['DW_AT_name'].value

def find_spec_name(CU, spec_off):
    for DIE in CU.iter_DIEs():
        if DIE.offset == spec_off:
            try:
                return get_name(DIE)
            except KeyError:
                pass
            pass
        pass
    pass

def decode_func_name_CU(CU, addr):
    for DIE in CU.iter_DIEs():
        try:
            if DIE.tag != 'DW_TAG_subprogram':
                continue
            lowpc = DIE.attributes['DW_AT_low_pc'].value
            hipc = DIE.attributes['DW_AT_high_pc'].value
            if lowpc <= addr <= hipc:
                try:
                    return get_name(DIE)
                except KeyError:
                    spec_off = DIE.attributes['DW_AT_specification'].value
                    spec_off = spec_off + CU.cu_offset
                    return find_spec_name(CU, spec_off)
                pass
            pass
        except KeyError:
            pass
        pass
    pass


def check_addr_in_CU(CU, addr):
    dwarf = CU.dwarfinfo
    try:
        range_lists = dwarf.range_lists_cache
    except AttributeError:
        range_lists = dwarf.range_lists()
        dwarf.range_lists_cache = range_lists
        pass
    DIE = CU.get_top_DIE()
    try:
        ranges_offset = DIE.attributes['DW_AT_ranges'].value
        range_list = range_lists.get_range_list_at_offset(ranges_offset)
        for entry in range_list:
            if entry.begin_offset <= addr < entry.end_offset:
                return True
            pass
        pass
    except KeyError:
        pass
    return False


def decode_func_name(dwarf, addr):
    for CU in dwarf.iter_CUs():
        if check_addr_in_CU(CU, addr):
            return decode_func_name_CU(CU, addr)
        pass
    pass


def decode_file_line(dwarf, addr):
    for CU in dwarf.iter_CUs():
        if not check_addr_in_CU(CU, addr):
            continue
        
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
    pass


if __name__ == '__main__':
    import sys, pprint
    filename = sys.argv[1]
    log = uncall_log()
    log.load(filename)

    print_flows_symbols(log)
    pass
