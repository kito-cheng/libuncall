# -*- Mode: python; tab-width: 4; indent-tab-mode: nil; py-indent-offset: 4 -*-
from elftools.elf.elffile import ELFFile
import re, bisect
import gc
import asyncore


reo_mapsline = re.compile('([0-9a-f]+) ([^ ]+)')

class maps(object):
    def __init__(self):
        super(maps, self).__init__()
        self._maps = []
        self._bases = []
        self._last_lookup_cache = (None, None, None, None)
        pass
    
    def load(self, lines):
        for line in lines:
            self.parse_line(line)
            pass
        self.sort_maps()
        self._bases = [base for base, filename in self._maps]
        pass
    
    def parse_line(self, line):
        mo = reo_mapsline.match(line)
        if not mo:
            return
        item = (int(mo.group(1), 16),
                mo.group(2))
        self._maps.append(item)
        pass

    def sort_maps(self):
        self._maps.sort(key=lambda x: x[0])
        pass

    def lookup_address(self, address):
        if address == self._last_lookup_cache[0]:
            return self._last_lookup_cache[1:]

        idx = bisect.bisect_right(self._bases, address) - 1
        if idx >= 0:
            base, filename = self._maps[idx]
            self._last_lookup_cache = (address, base, filename)
            return (base, filename)
        pass

    def lookup_address_rel(self, address):
        value = self.lookup_address(address)
        if value is not None:
            base, filename = value
            return address - base, filename
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
        maps_lines = [line[4:].strip()
                      for line in lines if line.startswith('MAP:')]
        flows_lines = [line[5:].strip()
                       for line in lines if line.startswith('FLOW:')]

        self.maps.load(maps_lines)
        self.flows.load(flows_lines)
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

def _filter_CU_DIEs(CU):
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

def _install_CU_DIEs(CU, DIEs):
    CU.DIEs_filtered_cache = DIEs
    pass


class ELF_manager(object):
    _elfs_cache = {}
    
    @classmethod
    def get_elf(self, so):
        if so not in self._elfs_cache:
            try:
                fo = file(so, 'r')
            except:
                return
            elf = ELFFile(fo, bytesio=False)
            self._elfs_cache[so] = elf
            pass

        elf = self._elfs_cache[so]
        return elf
    pass


def _get_elf_dwarf(elf):
    if not hasattr(elf, '_dwarf_cache'):
        elf._dwarf_cache = elf.get_dwarf_info()
        pass
    dwarf = elf._dwarf_cache
    return dwarf


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
        elf = ELF_manager.get_elf(so)
        
        return elf, rel
    
    def addr_to_CU_rel(self, addr):
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
        dwarf = _get_elf_dwarf(elf)
        CU = _CU_finder.addr_to_CU(dwarf, laddr)
        if CU is None:
            return
        
        self._last_CU, self._last_laddr, self._last_addr = CU, laddr, addr
        
        return CU, laddr

    def decode_func_name(self, addr):
        CU_rel = self.addr_to_CU_rel(addr)
        if CU_rel is None:
            return
        CU, rel = CU_rel
        func_name = decode_func_name(CU, rel)
        return func_name

    def decode_file_line(self, addr):
        CU_rel_pair = self.addr_to_CU_rel(addr)
        found_CU = CU_rel_pair is not None
        rv = (found_CU
              and decode_file_line(*CU_rel_pair)   # (file, line) pair
              or None)
        return rv
    pass


def print_flows_symbols(log, concurrent=1):
    result_cache = {}
    resolver = dwarf_resolver(log)

    if concurrent > 1:
        _concurrent_prepare_DIEs(concurrent, resolver, log)
        pass
    
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


def print_flows_dot(log, concurrent=1):
    resolver = dwarf_resolver(log)
    
    if concurrent > 1:
        _concurrent_prepare_DIEs(concurrent, resolver, log)
        pass
    
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
    for DIE in _filter_CU_DIEs(CU):
        if DIE['offset'] == spec_off:
            try:
                return get_name(DIE)
            except KeyError:
                pass
            pass
        pass
    pass

def decode_func_name_CU(CU, addr):
    for DIE in _filter_CU_DIEs(CU):
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
        top_DIE = CU.get_top_DIE()
        
        if not top_DIE.attributes.has_key('DW_AT_ranges'):
            try:
                low = top_DIE.attributes['DW_AT_low_pc'].value
                high = top_DIE.attributes['DW_AT_high_pc'].value
                return [(low, high)]
            except KeyError:
                return []
        
        range_offset = top_DIE.attributes['DW_AT_ranges'].value
        range_lists = CU.dwarfinfo.range_lists()
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
        
        closest_idx = min(bisect.bisect_right(sorted_map_low, addr),
                          len(sorted_map_low) - 1)
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


class slave_server(object):
    @staticmethod
    def parse_CU_DIEs(so_fname, CU_addr):
        elf = ELF_manager.get_elf(so_fname)
        dwarf = _get_elf_dwarf(elf)
        CU = _CU_finder.addr_to_CU(dwarf, CU_addr)
        DIEs = _filter_CU_DIEs(CU)
        return DIEs
    
    @staticmethod
    def run():
        from sys import stdin, stdout, stderr
        from base64 import b64encode

        while True:
            lines = []
            line = stdin.readline().strip()
            while line:
                if line.startswith('last: '):
                    lines.append(line[6:])
                    break
                if line.startswith('cont: '):
                    lines.append(line[6:])
                else:
                    raise ValueError, 'Invalid format "%s"' % line
                line = stdin.readline().strip()
                pass
            
            if len(lines) == 0:
                break
            
            cmd = lines[0]
            if cmd == 'parse_CU_DIEs':
                so_fname = lines[1].strip()
                CU_addr = int(lines[2].strip())
                
                DIEs = slave_server.parse_CU_DIEs(so_fname, CU_addr)
                reply = b64encode(repr((so_fname, CU_addr, DIEs)))
                
                start, end = 0, 64
                while end < len(reply):
                    print >> stdout, 'cont: %s' % reply[start:end]
                    start = end
                    end = end + 64
                    pass
                if start < len(reply):
                    print >> stdout, 'last: %s' % reply[start:]
                    pass
                
                stdout.flush()
                pass
            pass
        pass
    pass


class slave_handler(asyncore.file_dispatcher):
    def __init__(self, master, slave):
        asyncore.file_dispatcher.__init__(self, slave.stdout)
        self._master = master
        self._slave = slave
        self._data_queue = ''
        slave.stdout.close()
        pass

    def writable(self):
        return False

    def _handle_reply(self, lines):
        from base64 import b64decode
        
        _lines = [line[6:].strip() for line in lines]
        reply_msg = b64decode(''.join(_lines))
        reply = eval(reply_msg)
        
        so, addr, DIEs = reply
        self._master.handle_reply(so, addr, DIEs)
        self._master.slave_go_idle(self._slave)
        pass

    def handle_read(self):
        buf = self.recv(1024)
        self._data_queue = self._data_queue + buf
        
        lines = self._data_queue.split('\n')
        self._data_queue = lines[-1]
        
        cmd_lines = []
        for line in lines[:-1]:
            line = line.strip()
            if not line:
                continue

            cmd_lines.append(line)
            
            if line.startswith('last: '):
                self._handle_reply(cmd_lines)
                cmd_lines = []
                pass
            pass
        pass
    pass

class _concurrent_master(object):
    def __init__(self, concurrent, dwarf_resolver, log):
        super(_concurrent_master, self).__init__()
        self._concurrent = concurrent
        self._dwarf_resolver = dwarf_resolver
        self._log = log
        self._all_CUs = set()
        self._all_slaves = []
        self._all_slave_handlers = []
        pass

    def _start_slave(self):
        import subprocess, sys
        
        slave = subprocess.Popen(['python', sys.argv[0], '--slave'],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)
        
        return slave

    def _start_slaves(self):
        self._all_slaves = [self._start_slave()
                            for i in range(self._concurrent)]
        self._all_slave_handlers = [slave_handler(self, slave)
                                    for slave in self._all_slaves]
        pass

    def _stop_slaves(self):
        for slave in self._all_slaves:
            slave.kill()
            pass
        self._all_slaves = []
        pass

    def _make_CU_DIEs_task(self, addr):
        log = self._log
        dwarf_resolver = self._dwarf_resolver
        all_CUs = self._all_CUs

        rel_so_pair = log.maps.lookup_address_rel(addr)
        if rel_so_pair is not None:
            rel, so = rel_so_pair
            CU_rel = dwarf_resolver.addr_to_CU_rel(addr)
            if (CU_rel is not None) and (CU_rel[0] not in self._all_CUs):
                CU, rel = CU_rel
                all_CUs.add(CU)
                return (so, rel, CU)
            pass
        return None

    def _feed_idle_slaves(self):
        while self._idle_slaves and self._waiting:
            slave = self._idle_slaves[0]
            self._busy_slaves.append(slave)
            del self._idle_slaves[0]
            
            so, addr, CU = self._waiting[0]
            self._running.append(self._waiting[0])
            del self._waiting[0]
            
            print >> slave.stdin, 'cont: parse_CU_DIEs'
            print >> slave.stdin, 'cont: %s' % so
            print >> slave.stdin, 'last: %s' % addr
            pass
        pass

    def handle_reply(self, so, addr, DIEs):
        for i, (_so, _addr, CU) in enumerate(self._running):
            if _so == so and _addr == addr:
                _install_CU_DIEs(CU, DIEs)
                del self._running[i]
                return
            pass
        raise ValueError, 'invalid reply %x@%s' % (addr, so)

    def slave_go_idle(self, slave):
        if slave not in self._busy_slaves:
            raise RuntimeError, 'unknown slave!'
        
        self._busy_slaves.remove(slave)
        self._idle_slaves.append(slave)
        pass

    def _wait_busy_slaves(self):
        if self._busy_slaves:
            asyncore.loop(count=1)
            pass
        pass

    def _dispatch_tasks(self):
        self._waiting = list(self._all_tasks)
        self._running = []
        
        self._idle_slaves = list(self._all_slaves)
        self._busy_slaves = []
        
        while self._waiting or self._running:
            self._feed_idle_slaves()
            self._wait_busy_slaves()
            pass
        pass
    
    def prepare_DIEs(self):
        self._start_slaves()
        
        log = self._log
        all_addrs = sorted(set([addr for flow in log.flows for addr in flow]))
        all_tasks = set([self._make_CU_DIEs_task(addr)
                         for addr in all_addrs])
        if None in all_tasks:
            all_tasks.remove(None)
            pass

        self._all_tasks = list(all_tasks)
        self._dispatch_tasks()
        
        self._stop_slaves()
        pass
    pass

def _concurrent_prepare_DIEs(concurrent, dwarf_resolver, log):
    master = _concurrent_master(concurrent, dwarf_resolver, log)
    master.prepare_DIEs()
    pass


if __name__ == '__main__':
    import sys, pprint, optparse
    
    parser = optparse.OptionParser()
    parser.add_option('-d', '--dot', dest='dot',
                      action='store_true', default=False,
                      help='Create dot graph!')
    parser.add_option('-j', dest='concurrent',
                      default=1, type='int',
                      help='Concurrent level!')
    parser.add_option('--slave', dest='slave',
                      action='store_true', default=False,
                      help='This is internal command of uncalllog.py' + \
                        ' for concurrent!')
    options, args = parser.parse_args()

    if options.slave:
        slave_server.run()
        sys.exit(0)
        
    filename = args[0]
    log = uncall_log()
    log.load(filename)

    if options.dot:
        print_flows_dot(log, options.concurrent)
    else:
        print_flows_symbols(log, options.concurrent)
        pass
    pass
