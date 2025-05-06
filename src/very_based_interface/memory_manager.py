from .types import TYPES
from dissect.cstruct import Structure
from dissect.cstruct.utils import p64, u64

from typing import NamedTuple


class AliasRange(NamedTuple):
    source: Structure
    dest: Structure
    size: int


PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
assert PAGE_SIZE == 0x1000


class MemoryManager:
    physical_base_address: int
    base_page_table_pfn: int
    memory: bytearray

    aliased_ranges: list[AliasRange]

    def set_physical_base(self, base: int):
        self.physical_base_address = self.parse_pa(base).address

    def set_page_table_base(self, page_table_pa: int):
        address = self.parse_pa(page_table_pa).address
        assert address & (PAGE_SIZE - 1) == 0, "Unaligned page table base"

        self.base_page_table_pfn = address >> PAGE_SHIFT

    def set_memory(self, memory: bytearray):
        self.memory = memory

    @staticmethod
    def align(addr: int):
        return ((addr - 1) | (PAGE_SIZE - 1)) + 1

    @staticmethod
    def pfn_to_pa(pfn: int):
        return pfn << PAGE_SHIFT

    @staticmethod
    def parse_pte(pte: int | Structure) -> Structure:
        if isinstance(pte, TYPES.PtEntry):
            return pte

        return TYPES.PtEntry(p64(pte))

    @staticmethod
    def parse_va(va: int | Structure) -> Structure:
        if isinstance(va, TYPES.VirtualAddress):
            return va

        return TYPES.VirtualAddress(p64(va))

    @staticmethod
    def parse_pa(pa: int | Structure) -> Structure:
        if isinstance(pa, TYPES.PhysicalAddress):
            return pa

        return TYPES.PhysicalAddress(p64(pa))

    def read_offset(self, offset: int, size: int = 0):
        if size == 0:
            return self.memory[offset:]
        else:
            return self.memory[offset : offset + size]

    def write_offset(self, offset: int, data: bytes):
        self.memory[offset : offset + len(data)] = data

    def pa_to_offset(self, pa: int | Structure) -> int:
        addr = self.parse_pa(pa)

        aliased_offset = self.get_aliased_dest(addr)
        if aliased_offset is not None:
            return self.pa_to_offset(aliased_offset)

        return addr.address - self.physical_base_address

    def offset_to_pa(self, offset: int) -> int:
        addr = TYPES.PhysicalAddress()
        addr.address = offset + self.physical_base_address
        return u64(addr.dumps())

    def read_physical(self, pa: int | Structure, size: int = 0):
        return self.read_offset(self.pa_to_offset(pa), size)

    def write_physical(self, pa: int | Structure, data: bytes):
        return self.write_offset(self.pa_to_offset(pa), data)

    def va_to_pa(self, va: int | Structure) -> int:
        assert self.base_page_table_pfn != 0, (
            "Page table needed for translating virtual addresses"
        )

        def read_pte_entry(base_pfn: int, pte_index: int) -> Structure:
            pte_offset = pte_index * TYPES.PtEntry.size
            table_base_pa = self.pfn_to_pa(base_pfn)
            pte = TYPES.PtEntry(self.read_physical(table_base_pa + pte_offset, 8))
            assert pte.valid, (
                f"Invalid PTE read @ {hex(self.pa_to_offset(table_base_pa + pte_offset))}: {pte}"
            )
            assert not pte.large_page, "TODO: Large Page"
            return pte

        addr = self.parse_va(va)
        pml4 = read_pte_entry(self.base_page_table_pfn, addr.pml4_index)
        pdpt = read_pte_entry(pml4.page_frame_number, addr.pdpt_index)
        pd = read_pte_entry(pdpt.page_frame_number, addr.pd_index)
        pt = read_pte_entry(pd.page_frame_number, addr.pt_index)

        assert pt.accessed, "Invalid final PT entry"
        val = self.pfn_to_pa(pt.page_frame_number) + addr.page_offset
        return val

    def va_to_offset(self, va: int | Structure) -> int:
        return self.pa_to_offset(self.va_to_pa(va))

    def read_virtual(self, va: int | Structure, size: int = 0):
        return self.read_offset(self.va_to_offset(va), size)

    def write_virtual(self, va: int | Structure, data: bytes):
        return self.write_offset(self.va_to_offset(va), data)

    def get_aliased_dest(self, pa: int | Structure) -> int | None:
        pa = self.parse_pa(pa)

        for range in self.aliased_ranges:
            src = range.source

            if src.address > pa.address:
                continue

            if pa.address >= src.address + range.size:
                continue

            return range.dest.value + (pa.address - src.address)

        return None

    def add_aliased_range(
        self, source_pa: int | Structure, dest_pa: int | Structure, size: int
    ):
        self.aliased_ranges.append(
            AliasRange(
                source=self.parse_pa(source_pa), dest=self.parse_pa(dest_pa), size=size
            )
        )

    def __init__(self) -> None:
        self.aliased_ranges = []
        pass
