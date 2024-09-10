from .types import TYPES, AslrRelocationType, AslrSectionType, VbiDirectories, VbiVersion, va, pa, pte
from .memory_manager import MemoryManager, PAGE_SHIFT, PAGE_SIZE
from typing import BinaryIO
from dissect.cstruct import Structure
from io import BytesIO
from dissect.cstruct.utils import u16, u64, p64, dumpstruct
import os
import pefile
from rich import print

class VbiFile(MemoryManager):
    header: Structure
    header_data: bytearray
    version: VbiVersion
    debug_logging: bool

    def __init__(self, fp: BinaryIO, debug_logging: bool = False) -> None:
        super().__init__()
        self.debug_logging = debug_logging

        self.header = TYPES.VbiHeader(fp)
        assert bytes(self.header.magic) == b"1IBV", f"Invalid VBI magic: {bytes(self.header.magic)}"
        self.set_physical_base(self.header.physical_base_address)
        self.version = self.header.version

        assert self.version != VbiVersion.Version1, "VBIs of version 1 are not supported."

        fp.seek(0)
        self.header_data = bytearray(fp.read(self.header.header_size))
        assert len(self.header_data) == self.header.header_size, "Invalid header size"

        fp.seek(self.header.data_offset)
        data = bytearray(fp.read(self.header.data_size))
        assert len(data) == self.header.data_size, "Invalid header data size"
        self.set_memory(data)

    @staticmethod
    def print_address(addr):
        if isinstance(addr, int):
            return hex(addr)
        else:
            return hex(u64(addr.dumps()))

    def read_sized_struct(self, offset: int, name: str) -> Structure:
        struct_type = getattr(TYPES, name)
        struct_size = struct_type.size
        instance = struct_type(self.read_offset(offset, struct_size))
        if instance.size != struct_size:
            struct_type = getattr(TYPES, f"{name}_{instance.size:X}")
            instance = struct_type(self.read_offset(offset, struct_type.size))

        return instance
    
    def load_sized_struct(self, data: bytes, name: str) -> Structure:
        struct_type = getattr(TYPES, name)
        struct_size = struct_type.size
        if struct_size != len(data):
            struct_type = getattr(TYPES, f"{name}_{len(data):X}")
        
        return struct_type(data)

    def read_unicode(self, string: Structure) -> str:
        return self.read_virtual(string.buffer, string.length).decode("utf-16le")
    
    def read_str(self, va: int | Structure) -> str:
        return TYPES.char[None](self.read_virtual(va)).decode()

    def get_directory(self, index: VbiDirectories) -> bytearray | None:
        assert VbiDirectories.MaxDirectory > index, "Tried to get undefined VBI directory"

        if index >= len(self.header.directories):
            return None
        
        directory_info = self.header.directories[index]
        if directory_info.offset == 0 and directory_info.size == 0:
            return None
        
        return self.header_data[directory_info.offset:(directory_info.offset+directory_info.size)]

    def read_list(self, head: Structure, entry_type: type, callback):
        first = head.first
        last = head.last
        if first == 0 and last == 0:
            return
        
        current = first
        while True:
            entry = entry_type(self.read_virtual(current, entry_type.size))
            if entry.next == first and entry.previous == last:
                # This is the list head
                return
            
            callback(entry)
            current = entry.next

    def _load_aslr(self) -> None:
        # Normally this does both ASLR and Relocations...
        # ...we just skip the ASLR part though

        directory = self.get_directory(VbiDirectories.Aslr)
        if not directory:
            if self.debug_logging: print("No ASLR directory present.")
            return
        
        aslr_directory = TYPES.VbiDirectoryAslr(directory)
        aslr_header = aslr_directory.header

        if self.debug_logging:
            dumpstruct(aslr_header, color=False)
            print(f"ASLR entry count: {hex(aslr_directory.entry_count)}")
            print(f"ASLR base: {hex(aslr_header.aslr_base_address_va)}")
            print(f"ASLR page table base: {hex(aslr_header.aslr_page_table_base_pa)}")

        aslr_base_address: Structure = va(aslr_header.aslr_base_address_va)

        base_aslr_pte_pa: int = aslr_header.aslr_page_table_base_pa
        base_aslr_pte_pa += TYPES.PtEntry.size * aslr_base_address.pt_index

        section_start_aslr_pte_pa: int = base_aslr_pte_pa
        section_aslr_base_address: int = aslr_header.aslr_base_address_va

        last_section_page_count: int = 0

        for section in aslr_directory.entries:
            if self.debug_logging: 
                print(f"ASLRS: Type {section.type}")
                print(f"ASLRS: Skip Data Section: {section.skip_data_section}")
                print(f"ASLRS: Data Length: {hex(len(bytes(section.data)))}")
                print(f"ASLRS: Data: {bytes(section.data).hex()}")

            assert section.type in [0, 1, 2, 3, 4], f"Invalid ASLR Section type found"

            if last_section_page_count != 0:
                if section.type != AslrSectionType.Data:
                    last_section_page_count = (aslr_header.base_entry_page_count + last_section_page_count + 15) & 0xFFFFFFF0
                
                last_section_size = last_section_page_count << PAGE_SHIFT
                if self.debug_logging: 
                    print(f"ASLR: aslr_pte_offset ({hex(section_start_aslr_pte_pa)}) += {hex(8 * last_section_page_count)}")
                    print(f"ASLR: aslr_base_address ({hex(section_aslr_base_address)}) += {self.print_address(last_section_size)}")

                section_start_aslr_pte_pa += TYPES.PtEntry.size * last_section_page_count
                section_aslr_base_address += last_section_size

            last_section_page_count = section.page_count
            section_data = BytesIO(bytes(section.data))

            current_section_aslr_pte_pa = section_start_aslr_pte_pa
            remaining = section.page_count
            if self.debug_logging: print(f"ASLRS: Page count: {hex(remaining)}")
            while remaining != 0:
                start_pte = TYPES.PtEntry(section_data.read(TYPES.PtEntry.size))
                segment_page_count = start_pte.reserved + 1

                if self.debug_logging: 
                    print(f"ASLRS: Segment PT base: {start_pte}")
                    print(f"ASLRS: Segment page count: {hex(segment_page_count)}")

                current_pte = start_pte.value & 0x8000FFFFFFFFFFFF

                for _ in range(segment_page_count):
                    if self.debug_logging:
                        pte_phys = self.print_address(current_section_aslr_pte_pa)
                        pte_offset = self.print_address(self.pa_to_offset(current_section_aslr_pte_pa))
                        current_pfn = pte(current_pte).page_frame_number
                        pt_target_off = self.print_address(self.pa_to_offset(self.pfn_to_pa(current_pfn)))
                        print(f"ASLRSPT: {pte_phys} ({pte_offset}) == {pte(current_pte)} ({pt_target_off})")

                    self.write_physical(current_section_aslr_pte_pa, p64(current_pte))
                    remaining -= 1
                    current_pte += PAGE_SIZE
                    current_section_aslr_pte_pa += TYPES.PtEntry.size

            if self.debug_logging:
                print(f"ASLRS: Finished parsing @ data offset {hex(section_data.tell())}")

            while section_data.tell() != len(section.data):
                if self.debug_logging:
                    print(f"ASLRR: Parsing new relocation entry @ data offset {hex(section_data.tell())}")

                relocation_entry = TYPES.AslrRelocationEntry(section_data.read(TYPES.AslrRelocationEntry.size))
                match relocation_entry.type:
                    case AslrRelocationType.Relative:
                        base = relocation_entry.relative.base
                        count = relocation_entry.relative.count
                        if self.debug_logging:
                            print(f"ASLRR0: Base {pa(relocation_entry.relative.base)}")
                            print(f"ASLRR0: Entry count {hex(count)}")

                        for _ in range(count):
                            offset = u16(section_data.read(2))
                            if offset >= 0x8000:
                                target = base + (offset & 0x7FFF)
                                if self.debug_logging: 
                                    target_addr = self.print_address(target)
                                    offset_addr = self.print_address(self.pa_to_offset(target))
                                    current_aslr_addr = self.print_address(section_aslr_base_address)
                                    print(f"ASLRR0: {target_addr} ({offset_addr}) += {current_aslr_addr}")

                                original = u64(self.read_physical(target, 8))
                                self.write_physical(target, p64(original + section_aslr_base_address))
                    
                    case AslrRelocationType.Absolute:
                        target = u64(section_data.read(8))
                        addend = relocation_entry.absolute.addend
                        if self.debug_logging: 
                            target_addr = self.print_address(target)
                            offset_addr = self.print_address(self.pa_to_offset(target))
                            addend_val = self.print_address(addend)
                            current_aslr_addr = self.print_address(section_aslr_base_address)
                            print(f"ASLRR1: {target_addr} ({offset_addr}) = {current_aslr_addr} + {addend_val}")

                        self.write_physical(target, p64(section_aslr_base_address + addend))
                    
                    case AslrRelocationType.EnvironmentRelative:
                        offset = relocation_entry.environment_relative.environment_offset
                        env = self.get_directory(VbiDirectories.Environment)
                        original = u64(env[offset:offset+8])
                        if self.debug_logging:
                            current_aslr_addr = self.print_address(section_aslr_base_address)
                            print(f"ASLRR2: environment @ {self.print_address(offset)} += {current_aslr_addr}")

                        env[offset:offset+8] = p64(original + section_aslr_base_address)

                    case _:
                        assert False, f"Invalid ASLR relocation type {hex(relocation_entry.type)} encountered."

            assert len(section_data.read()) == 0

        aslr_pt_count = (section_start_aslr_pte_pa - 1 + TYPES.PtEntry.size * last_section_page_count) >> PAGE_SHIFT
        aslr_pt_count -= aslr_header.aslr_page_table_base_pa >> PAGE_SHIFT
        aslr_pt_count += 1

        aslr_pd_count = (TYPES.PtEntry.size * (section_aslr_base_address - 1 + (last_section_page_count << PAGE_SHIFT) >> 21)) >> PAGE_SHIFT
        aslr_pd_count -= (TYPES.PtEntry.size * (section_aslr_base_address >> 21)) >> PAGE_SHIFT
        aslr_pd_count += 1 

        if self.debug_logging:
            print(f"ASLR PT Count: {hex(aslr_pt_count)}")
            print(f"ASLR PD Count: {hex(aslr_pd_count)}")

        page_difference = aslr_header.max_page_count - aslr_pt_count - aslr_pd_count
        assert page_difference >= 0, "ASLR used too many page table pages"

        self.write_physical(aslr_header.unk_memory_descriptor_page_count_sub_pa, p64(u64(self.read_physical(aslr_header.unk_memory_descriptor_page_count_sub_pa, 8)) - page_difference))
        self.write_physical(aslr_header.unk_memory_descriptor_page_count_sub1_pa, p64(u64(self.read_physical(aslr_header.unk_memory_descriptor_page_count_sub1_pa, 8)) - page_difference))
        self.write_physical(aslr_header.unk_memory_descriptor_page_count_add_pa, p64(u64(self.read_physical(aslr_header.unk_memory_descriptor_page_count_add_pa, 8)) + page_difference))

        base_pd_pa = base_aslr_pte_pa + TYPES.PtEntry.size * (aslr_pt_count << 9)
        base_pd_pte = aslr_header.aslr_page_table_base_pa | 0x63

        current_pd_pa = base_pd_pa
        current_pd_pte = base_pd_pte
        for _ in range(aslr_pt_count):
            if self.debug_logging: 
                current_pd_addr = self.print_address(self.pa_to_offset(current_pd_pa))
                print(f"ASLRPD: {current_pd_addr} == {pte(current_pd_pte)}")

            self.write_physical(current_pd_pa, p64(current_pd_pte))
            current_pd_pa += TYPES.PtEntry.size
            current_pd_pte += PAGE_SIZE

        base_pdpt_pa = aslr_header.aslr_pdpt_base_pa + TYPES.PtEntry.size * (aslr_base_address.pdpt_index)

        current_pdpt_pa = base_pdpt_pa
        current_pdpt_pte = current_pd_pte
        for _ in range(aslr_pd_count):
            if self.debug_logging: 
                current_pdpt_addr = self.print_address(self.pa_to_offset(current_pdpt_pa))
                print(f"ASLRPDPT: {current_pdpt_addr} == {pte(current_pdpt_pte)}")
                
            self.write_physical(current_pdpt_pa, p64(current_pdpt_pte))
            current_pdpt_pa += TYPES.PtEntry.size
            current_pdpt_pte += PAGE_SIZE

    def load(self) -> None:
        self._load_aslr()
        
        env_dir = self.get_directory(VbiDirectories.Environment)
        self._environment = TYPES.VbiDirectoryEnvironment(env_dir)

        loader_block_directory = self.get_directory(VbiDirectories.LoaderBlock)
        if loader_block_directory:
            loader_block = self.load_sized_struct(loader_block_directory, "VbiDirectoryLoaderBlock")
            self.set_page_table_base(loader_block.kernel_page_table_pa)
        else:
            self.set_page_table_base(self._environment.kernel_page_table_pa)

    def dump_files(self, output_root: str):
        os.makedirs(output_root, exist_ok=True)

        loader_block_va = 0

        loader_block_directory = self.get_directory(VbiDirectories.LoaderBlock)
        if loader_block_directory:
            vbi_loader_block = self.load_sized_struct(loader_block_directory, "VbiDirectoryLoaderBlock")
            loader_block_va = vbi_loader_block.kernel_loader_block_va
        else:
            loader_block_va = self._environment.kernel_loader_block_va

        loader_block = self.read_sized_struct(self.va_to_offset(loader_block_va), "LoaderBlock")

        def on_loader_data_table_entry(entry):
            dll_name = self.read_unicode(entry.base_dll_name)
            print(f"[bold grey]Dumping [bold white]{dll_name}[/]...[/]", end=" ")

             # first read mapped pe image
            header = self.read_virtual(entry.dll_base, PAGE_SIZE)
            executable = pefile.PE(data=header, fast_load=True)

            with open(f"{output_root}/{dll_name}", "wb+") as f:
                # patch base address
                header = bytearray(executable.header)
                image_base_offset = executable.OPTIONAL_HEADER.get_file_offset() + 0x18 # type: ignore
                header[image_base_offset:image_base_offset+0x8] = entry.dll_base.dumps()
                f.write(header)

                for section in executable.sections:
                    if section.SizeOfRawData == 0:
                        continue

                    current = entry.dll_base + section.VirtualAddress
                    remaining = section.SizeOfRawData
                    f.seek(section.PointerToRawData)

                    while remaining != 0:
                        current_block = min(remaining, executable.OPTIONAL_HEADER.FileAlignment)
                        data = self.read_virtual(current, current_block)
                        assert len(data) == current_block, f"Reading at {self.print_address(self.va_to_offset(current))} failed"
                        f.write(data)
                        current += current_block
                        remaining -= current_block

            
            print(f"[bold green]success[/]")

        self.read_list(loader_block.load_order_list, TYPES.LoaderDataTableEntry, on_loader_data_table_entry)