# -*- Mode: python; tab-width: 4; indent-tab-mode: nil; py-indent-offset: 4 -*-
from elftools.elf.elffile import ELFFile
import re, bisect
import gc


reo_mapsline = re.compile('([0-9a-f]+)-([0-9-a-f]+) ..x. ([0-9a-f]+) ([0-9:]+) ([0-9]+) *([^ ]+)')

class maps(object):
    def __init__(self):
        super(maps, self).__init__()
        self._maps = []
        self._last_lookup_cache = (None, None, None, None)
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
        if address == self._last_lookup_cache[0]:
            return self._last_lookup_cache[1:]
        
        for start, stop, filename in self._maps:
            if address >= start and address < stop:
                self._last_lookup_cache = (address, start, stop, filename)
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


class dwarf_resolver(object):
    def __init__(self, log):
        super(dwarf_resolver, self).__init__()
        self._log = log
        self._elfs_cache = {}
        self._last_addr = None
        self._last_CU = None
        self._last_laddr = None
        pass

    def _find_elf(self, addr):
        rel_so = self._log.maps.lookup_address_rel(addr)
        if rel_so is None:
            return
        
        rel, so = rel_so
        if so not in self._elfs_cache:
            fo = file(so, 'r')
            elf = ELFFile(fo, bytesio=False)
            self._elfs_cache[so] = elf
            pass

        elf = self._elfs_cache[so]
        return elf, rel
    
    def _addr_to_CU(self, addr):
        if self._last_addr == addr:
            return self._last_CU, self._last_laddr
        
        elf_rel = self._find_elf(addr)
        if elf_rel is None:
            return
        
        elf, rel = elf_rel
        if elf['e_type'] == 'ET_EXEC':
            laddr = addr - 1      # for x86, IP is at next opcode.
        else:
            laddr = rel - 1       # for x86, IP is at next opcode.
            pass
        if not hasattr(elf, '_dwarf_cache'):
            elf._dwarf_cache = elf.get_dwarf_info()
        dwarf = elf._dwarf_cache
        CU = _CU_finder.addr_to_CU(dwarf, laddr)
        if CU is None:
            return
        
        self._last_CU, self._last_laddr, self._last_addr = CU, laddr, addr
        
        return CU, laddr

    def decode_func_name(self, addr):
        CU_rel = self._addr_to_CU(addr)
        if CU_rel is None:
            return
        CU, rel = CU_rel
        func_name = decode_func_name(CU, rel)
        return func_name

    def decode_file_line(self, addr):
        CU_rel_pair = self._addr_to_CU(addr)
        found_CU = CU_rel_pair is not None
        rv = (found_CU
              and decode_file_line(*CU_rel_pair)   # (file, line) pair
              or None)
        return rv
    pass


def print_flows_symbols(log):
    result_cache = {}
    resolver = dwarf_resolver(log)
    
    for i in range(len(log.flows)):
        print 'FLOW:'
        flow = log.flows[i]
        for addr in flow:
            if addr in result_cache:
                print '%s:%s:%s' % result_cache[addr]
                continue

            rel_so_pair = log.maps.lookup_address_rel(addr)
            if rel_so_pair is None:
                print '?:?:0x%x' % addr
                continue

            rel, so = rel_so_pair
            
            symbol = resolver.decode_func_name(addr)
            func_name = (symbol and symbol + '()'
                         or ('0x%x(rel:0x%x)' % (addr, rel)))
            filename, line = (resolver.decode_file_line(addr)
                              or (so, '?'))
            
            print '%s:%s:%s' % (filename, line, func_name)
            result_cache[addr] = (filename, line, func_name)
            pass
        
        print
        pass
    pass


def print_flows_dot(log):
    resolver = dwarf_resolver(log)
    all_addrs = set([addr
                     for flow in log.flows
                     for addr in flow])
    addr_name_pairs = [(addr,
                        resolver.decode_func_name(addr)
                        or ('addr@0x%x' % addr))
                       for addr in sorted(all_addrs)]
    addr_name_map = dict(addr_name_pairs)
    
    graph = {None: []}
    outgoing_count = {}
    for i in range(len(log.flows)):
        flow = log.flows[i]
        to = None
        for addr in flow:
            name = addr_name_map[addr]
            if name not in graph:
                graph[name] = []
                outgoing_count[name] = 0
                pass
            if name not in graph[to]:
                graph[to].append(name)
                outgoing_count[name] = outgoing_count[name] + 1
                pass
            to = name
            pass
        pass
    for src_name in graph[None]:
        outgoing_count[src_name] = outgoing_count[src_name] -1
        pass
    del graph[None]

    print 'digraph uncallutils {'
    
    terminals = ['\t"%s" [color=red];' % name
                 for name, count in outgoing_count.items()
                 if count == 0]
    print '\n'.join(terminals)
    
    edges = ['\t"%s" -> "%s";' % (src, to)
             for to, srcs in graph.items()
             for src in srcs]
    print '\n'.join(edges)
    
    print '}'
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
        def silence_fault_for_dwarf_iter_CUs():
            try:
                for CU in dwarf.iter_CUs():
                    yield CU
                    pass
            except AttributeError:           # No .debug_info section?
                pass
            pass
        CU_map = [(low, high, CU)
                  for CU in silence_fault_for_dwarf_iter_CUs()
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
        if len(sorted_map) == 0:
            return 0
        
        closest_idx = bisect.bisect_right(sorted_map_low, addr)
        #
        # Since all low addresses before this one are always lower
        # than or equal to this one, and the biggest high address
        # before thhis one is bigger than the value of addr, then
        # there must be some one earlier covering the value of addr.
        #
        while addr < sorted_map_high_before[closest_idx]:
            closest_idx = closest_idx - 1
            pass
        #
        # This is the index of the first range in the list covering
        # the value of addr if there is.  It promises to match the
        # first CU covering the value of addr since list.sort() of
        # Python is stable.
        #
        return closest_idx

    @staticmethod
    def addr_to_CU(dwarf, addr):
        sorted_map, sorted_map_low, sorted_map_high_before = \
          _CU_finder._sorted_CU_map(dwarf)
        
        closest_idx = _CU_finder._first_matched(dwarf, addr)
        if closest_idx >= len(sorted_map):
            return None
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
    import sys, pprint, optparse
    
    parser = optparse.OptionParser()
    parser.add_option('-d', '--dot', dest='dot',
                      action='store_true', default=False,
                      help='Create dot graph!')
    options, args = parser.parse_args()
    
    filename = args[0]
    log = uncall_log()
    log.load(filename)

    if options.dot:
        print_flows_dot(log)
    else:
        print_flows_symbols(log)
        pass
    pass
