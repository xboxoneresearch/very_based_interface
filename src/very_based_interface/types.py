from dissect.cstruct import cstruct, p64, u64, Structure
from enum import IntEnum

# not 100% sure about the proper meaning of some of these flags, but the general structure should be correct
# support for large pages is not guaranteed to work
MEMORY_TYPES = \
"""
union PtEntry {
    struct {
        uint64 valid : 1;
        uint64 dirty1 : 1;
        uint64 owner : 1;
        uint64 write_through : 1;
        uint64 cache_disable : 1;
        uint64 accessed : 1;
        uint64 dirty : 1;
        uint64 large_page : 1;
        uint64 global : 1;
        uint64 copy_on_write : 1;
        uint64 unused : 1;
        uint64 write : 1;
        uint64 page_frame_number : 36;
        uint64 reserved : 15;
        uint64 no_execute : 1;
    };

    uint64 value;
}

union VirtualAddress {
    struct {
        uint64 page_offset : 12;
        uint64 pt_index : 9;
        uint64 pd_index : 9;
        uint64 pdpt_index : 9;
        uint64 pml4_index : 9;
        uint64 address_type : 16;
    };

    uint64 value;
};
       
union PhysicalAddress {
    struct {
        uint64 address : 36;
        uint64 unknown : 28;
    };

    uint64 value;
};
"""
# all of these types are grabbed from a windows ntoskrnl pdb
LOADER_TYPES = \
"""
struct UnicodeString {
    uint16 length;
    uint16 maximum_length;
    uint64 buffer;
};


struct ListHead {
    uint64 first;
    uint64 last;
};

struct ListEntry {
    uint64 next;
    uint64 previous;
}

struct FirmwareInformationLoaderBlock {
    uint32 firmware_type_uefi : 1;
    uint32 efi_runtime_use_ium : 1;
    uint32 efi_runtime_page_protection_supported : 1;
    uint32 reserved : 29;
    uint32 padding; // bug

    uint32 firmware_version;
    uint64 virtual_efi_runtime_services;
    int32 set_virtual_address_map_status;
    uint32 missed_mappings_count;
    ListHead firmware_resource_list;
    uint64 efi_memory_map;
    uint32 efi_memory_map_size;
    uint32 efi_memory_map_descriptor_size;
};

struct RtlBalancedNode {
    uint64 left;
    uint64 right;
    uint64 parent_value;
};

struct RtlRbTree {
    uint64 root;
    uint64 other;
}

struct ArcDiskSignature {
   uint64 next;
   uint64 previous;

   uint32 signature;
   uint64 arc_name;
   uint32 checksum;
   uint8 valid_partition_table;
   uint8 x_int13;
   uint8 is_gpt;
   uint8 reserved;
   char gpt_signature[16]; 
};

struct ArcDiskInformation {
    ListHead disk_signatures; // ArcDiskSignature
}

struct BootDriverListEntry {
    uint64 next;
    uint64 previous;
    UnicodeString file_path;
    UnicodeString registry_path;
    uint64 ldr_entry;
    uint32 unknown;
};

struct CoreExtensionSubgroupInformation {
    uint64 next;
    uint64 previous;
    uint64 load_order_groups; // wchar**
    uint32 trust_validation_flags;
};

enum TYPE_OF_MEMORY : uint32
{
  LoaderExceptionBlock = 0x0,
  LoaderSystemBlock = 0x1,
  LoaderFree = 0x2,
  LoaderBad = 0x3,
  LoaderLoadedProgram = 0x4,
  LoaderFirmwareTemporary = 0x5,
  LoaderFirmwarePermanent = 0x6,
  LoaderOsloaderHeap = 0x7,
  LoaderOsloaderStack = 0x8,
  LoaderSystemCode = 0x9,
  LoaderHalCode = 0xA,
  LoaderBootDriver = 0xB,
  LoaderConsoleInDriver = 0xC,
  LoaderConsoleOutDriver = 0xD,
  LoaderStartupDpcStack = 0xE,
  LoaderStartupKernelStack = 0xF,
  LoaderStartupPanicStack = 0x10,
  LoaderStartupPcrPage = 0x11,
  LoaderStartupPdrPage = 0x12,
  LoaderRegistryData = 0x13,
  LoaderMemoryData = 0x14,
  LoaderNlsData = 0x15,
  LoaderSpecialMemory = 0x16,
  LoaderBBTMemory = 0x17,
  LoaderZero = 0x18,
  LoaderXIPRom = 0x19,
  LoaderHALCachedMemory = 0x1A,
  LoaderLargePageFiller = 0x1B,
  LoaderErrorLogMemory = 0x1C,
  LoaderVsmMemory = 0x1D,
  LoaderFirmwareCode = 0x1E,
  LoaderFirmwareData = 0x1F,
  LoaderFirmwareReserved = 0x20,
  LoaderEnclaveMemory = 0x21,
  LoaderFirmwareKsr = 0x22,
  LoaderEnclaveKsr = 0x23,
  LoaderSkMemory = 0x24,
  LoaderSkFirmwareReserved = 0x25,
  LoaderIoSpaceMemoryZeroed = 0x26,
  LoaderIoSpaceMemoryFree = 0x27,
  LoaderIoSpaceMemoryKsr = 0x28,
  LoaderKernelShadowStack = 0x29,
  LoaderIsolatedHostVisible = 0x2A,
  LoaderIsolatedKsr = 0x2B,
  LoaderMaximum = 0x2C,
};

struct MemoryDescriptorOld {
    uint64 next;
    uint64 previous;
    TYPE_OF_MEMORY memory_type;
    uint64 base_page_frame;
    uint64 page_count;
}

struct MemoryDescriptor {
    uint64 next;
    uint64 previous;
    uint64 flags;
    TYPE_OF_MEMORY memory_type;
    uint64 base_page_frame;
    uint64 page_count;
};

struct LoaderPerformanceData {
    uint64 start_time;
    uint64 end_time;
    uint64 preload_end_time;
    uint64 tcp_loader_start_time;
    uint64 load_hypervisor_time;
    uint64 launch_hypervisor_time;
    uint64 load_vsm_time;
    uint64 launch_vsm_time;
    uint64 execute_transition_start_time;
    uint64 execute_transition_end_time;
    uint64 load_drivers_time;
    uint64 cleanup_vsm_time;
};

struct BootEntropySourceLdrResult {
    uint32 source_id;
    uint64 policy;
    uint32 result_code;
    uint32 result_status;
    uint64 time;
    uint32 entropy_length;
    uint8 entropy_data[64];
}

struct BootEntropyLdrResult {
    uint32 max_entropy_sources;
    BootEntropySourceLdrResult entropy_source_result[10];
    uint8 seed_bytes_for_cng[48];
    uint8 rng_bytes_for_ntoskrnl[1024];
    uint8 kd_entropy[32];
}

struct LoaderParameterHypervisorExtension {
    uint32 initial_hypervisor_crashdump_area_page_count;
    uint32 hypervisor_crashdump_area_page_count;
    uint64 initial_hypervisor_crashdump_area_spa;
    uint64 hypervisor_crashdump_area_spa;
    uint64 hypervisor_launch_status;
    uint64 hypervisor_launch_status_arg1;
    uint64 hypervisor_launch_status_arg2;
    uint64 hypervisor_launch_status_arg3;
    uint64 hypervisor_launch_status_arg4;
}

struct LoaderBugcheckParameters {
    uint bugcheck_code;
    uint64 bugcheck_parameter_1;
    uint64 bugcheck_parameter_2;
    uint64 bugcheck_parameter_3;
    uint64 bugcheck_parameter_4;
}

struct OfflineCrashdumpConfigurationTableV2 {
    uint32 version;
    uint32 abnormal_reset_occured;
    uint32 offline_memory_dump_capable;
    uint64 reset_data_address;
    uint32 reset_data_slice;
};

struct LoaderHiveRecoveryInfo {
    uint32 flags;
    uint32 flags2;
    uint32 log_next_sequence;
    uint32 log_minimum_sequence;
    uint32 log_current_offset;
}

struct LoaderResetReason {
    uint8 supplied;
    uint64 basic;
    uint32 additional_info[8];
}

struct MiniExecutive {
    uint64 code_base;
    uint64 code_size;
}

struct VsmPerformanceData {
    uint64 launch_vsm_mark[8];
}

struct LoaderFeatureConfigurationInformation {
    uint64 feature_configuration_buffer;
    uint32 feature_configuration_buffer_size;
    uint64 usage_subscription_buffer;
    uint32 usage_subscription_buffer_size;
    uint64 delayed_usage_report_buffer;
    uint32 delayed_usage_report_buffer_size;
    uint8 diagnostic_information[0x18];
}

struct EtwBootConfig {
    uint32 max_loggers;
    ListHead boot_loggers_list;
}

struct InstalledMemoryRange {
    uint64 base_page;
    uint32 page_count;
}

struct InstalledMemory {
    uint64 ranges;
    uint32 range_count;
}

struct CimfsInformation {
    uint8 target_volume[0x10];
    uint64 cim_fimes;
    uint32 cim_files_count;
}

struct ProfileParameterBlock {
    uint16 status;
    uint16 reserved;
    uint16 docking_state;
    uint16 capabilities;
    uint32 dock_id;
    uint32 serial_number; 
}

// Latest - 0x170
// LOADER_PARAMETER_BLOCK 
struct LoaderBlock {
    uint32 os_major_version;
    uint32 os_minor_version;
    uint32 size;
    uint32 os_loader_security_version;
    ListHead load_order_list; // LoaderDataTableEntry
    ListHead memory_descriptor_list;
    ListHead boot_driver_list; // BootDriverListEntry
    ListHead early_launch_list; // LoaderDataTableEntry
    ListHead core_extensions_driver_list; // CoreExtensionSubgroupInformation
    ListHead tpm_core_driver_list; // BootDriverListEntry
    ListHead unknown_list;
    uint64 kernel_stack;
    uint64 prcb;
    uint64 process;
    uint64 thread;
    uint32 kernel_stack_size;
    uint32 registry_length;
    uint64 registry_base;
    uint64 configuration_root;
    uint64 arc_boot_device_name;
    uint64 arc_hal_device_name;
    uint64 nt_boot_path_name;
    uint64 nt_hal_path_name;
    uint64 load_options;
    uint64 nls_data;
    uint64 arc_disk_information;
    uint64 extension;
    uint8 processor_loader_block[0x10];
    FirmwareInformationLoaderBlock firmware_information;
    uint64 os_bootstat_path_name;
    uint64 arc_os_data_device_name;
    uint64 arc_windows_sys_part_name;
    RtlRbTree memory_descriptor_tree;
};

// Older versions
struct LoaderBlock_160 { // unverified
    uint32 os_major_version;
    uint32 os_minor_version;
    uint32 size;
    uint32 os_loader_security_version;
    ListHead load_order_list; // LoaderDataTableEntry
    ListHead memory_descriptor_list;
    ListHead boot_driver_list; // BootDriverListEntry
    ListHead early_launch_list; // LoaderDataTableEntry
    ListHead core_extensions_driver_list; // CoreExtensionSubgroupInformation
    uint64 kernel_stack;
    uint64 prcb;
    uint64 process;
    uint64 thread;
    uint32 kernel_stack_size;
    uint32 registry_length;
    uint64 registry_base;
    uint64 configuration_root;
    uint64 arc_boot_device_name;
    uint64 arc_hal_device_name;
    uint64 nt_boot_path_name;
    uint64 nt_hal_path_name;
    uint64 load_options;
    uint64 nls_data;
    uint64 arc_disk_information;
    uint64 extension;
    uint8 processor_loader_block[0x10];
    FirmwareInformationLoaderBlock firmware_information;
    uint64 os_bootstat_path_name;
    uint64 arc_os_data_device_name;
    uint64 arc_windows_sys_part_name;
    RtlRbTree memory_descriptor_tree;
};

struct LoaderBlock_B8 {
    uint32 os_major_version;
    uint32 os_minor_version;
    uint32 size;
    uint32 os_loader_security_version;
    uint64 registry_base;
    ListHead load_order_list; // LoaderDataTableEntry
    ListHead memory_descriptor_list;
    ListHead boot_driver_list; // BootDriverListEntry
    uint64 kernel_stack;
    uint64 prcb;
    uint64 process;
    uint64 thread;
    uint64 arc_boot_device_name;
    uint64 arc_hal_device_name;
    uint64 nt_boot_path_name;
    uint64 nt_hal_path_name;
    uint64 load_options;
    uint64 nls_data;
    uint64 arc_disk_information;
    uint64 extension;
    uint64 unknown19;
    RtlRbTree memory_descriptor_tree;
};

struct LoaderDataTableEntry {
    uint64 next; // ListHead in_load_order_links;
    uint64 previous;
    uint64 exception_table;
    uint32 exception_table_size;
    uint64 gp_value;
    uint64 non_paged_debug_info;
    uint64 dll_base;
    uint64 entry_point;
    uint32 size_of_image;
    UnicodeString full_dll_name;
    UnicodeString base_dll_name;
    uint32 flags;
    uint16 load_count;
    uint16 entire_field;
    uint64 section_pointer;
    uint32 checksum;
    uint32 coverage_section_size;
    uint64 coverage_section;
    uint64 loaded_imports;
    uint64 nt_data_table_entry;
    uint32 size_of_image_not_rounded;
    uint32 time_date_stamp;
    UnicodeString certificate_punlisher;
    UnicodeString certificate_issuer;
    uint64 image_hash;
    uint64 certificate_thumbprint;
    uint32 image_hash_algorithm;
    uint32 thumbprint_hash_algorithm;
    uint32 image_hash_length;
    uint32 certificate_thumbprint_length;
};

struct LoaderParameterExtension {
    uint32 size;
    ProfileParameterBlock profile;
    uint32 padding; // bug in dissect.cstruct
    uint64 em_inf_file_image;
    uint32 em_inf_file_size;
    uint64 triage_dump_block;
    uint64 headless_loader_block;
    uint64 smbios_eps_header;
    uint64 drv_db_image;
    uint32 drv_db_size;
    uint64 drv_db_patch_image;
    uint32 drv_db_patch_size;
    uint64 network_loader_block;
    ListHead firmware_descriptor_list_head;
    uint64 acpi_table;
    uint32 acpi_table_size;
    uint32 flags;
    LoaderPerformanceData loader_performance_data;
    ListHead boot_application_persistent_data;
    uint64 wmd_test_result;
    uint8 boot_identifier[16];
    uint32 resume_pages;
    uint64 dump_header;
    uint64 bg_context;
    uint64 numa_locality_info;
    uint64 numa_group_assignments;
    ListHead attached_hives;
    uint32 memory_caching_requirements_count;
    uint64 memory_caching_requirements;
    BootEntropyLdrResult boot_entropy_result;
    uint64 processor_count_frequency;
    LoaderParameterHypervisorExtension hypervisor_extension;
    uint8 hardware_configuration_id[16];
    ListHead hal_extension_module_list;
    ListHead prm_update_module_list;
    ListHead pfm_firmware_module_list;
    uint64 system_time;
    uint64 timestamp_at_system_time_read;
    uint64 boot_flags;
    uint64 internal_boot_flags;
    uint64 wfs_fp_data;
    uint32 wfs_fp_data_size;
    LoaderBugcheckParameters bugcheck_parameters;
    uint64 api_set_schema;
    uint32 api_set_schema_size;
    ListHead api_set_schema_extensions;
    UnicodeString acpi_bios_version;
    UnicodeString smbios_version;
    UnicodeString efi_version;
    uint64 kd_debug_device;
    OfflineCrashdumpConfigurationTableV2 offline_crashdump_configuration_table_v2;
    UnicodeString manufacturing_profile;
    uint64 bbt_buffer;
    uint64 xsave_allowed_features;
    uint64 xsave_flags;
    uint64 boot_options;
    uint32 ium_enablement;
    uint32 ium_policy;
    int32 ium_status;
    uint32 boot_id;
    uint64 code_integrity_data;
    uint32 code_integrity_data_size;
    LoaderHiveRecoveryInfo system_hive_recovery_info;
    uint32 soft_restart_count;
    uint64 soft_restart_time;
    uint64 hypercall_code_va;
    uint64 hal_virtual_address;
    uint64 hal_number_of_bytes;
    uint64 leap_second_data;
    uint32 major_release;
    uint32 reserved1;
    char nt_build_lab[224];
    char nt_build_lab_ex[224];
    LoaderResetReason reset_reason;
    uint32 max_pci_bus_number;
    uint32 feature_settings;
    uint32 hot_patch_reserve_size;
    uint32 retpoline_reserve_size;
    MiniExecutive mini_executive;
    VsmPerformanceData vsm_performance_data;
    uint64 numa_memory_ranges;
    uint32 numa_memory_ranges_count;
    uint32 iommu_fault_policy;
    LoaderFeatureConfigurationInformation feature_configuration_information;
    EtwBootConfig etw_boot_config;
    uint64 fw_ramdisk_info;
    uint64 ipmi_hw_context;
    uint64 idle_thread_shadow_stack;
    uint64 transition_shadow_stack;
    uint64 ist_shadow_stacks_table;
    uint64 reserved_for_kernel_cet[2];
    uint64 mirroring_data;
    uint64 luid;
    InstalledMemory installed_memory;
    ListHead hot_patch_list;
    uint64 bsp_microcode_data;
    uint32 bsp_microcode_data_size;
    CimfsInformation cimfs_information;
    uint64 hal_soft_reboot_database;
    uint32 flags2;
    uint64 performance_data_frequency;
}
"""

VBI_TYPES = \
"""
struct VbiDirectory {
    uint offset;
    uint size;
};

struct VbiHeader {
    uint8 magic[4];
    uint32 version;
    uint32 header_size;
    uint32 data_size;
    uint64 physical_base_address;
    uint64 unknown_addr;
    uint32 data_offset;
    uint32 flags;
    uint32 directory_count;
    VbiDirectory directories[directory_count];
};

struct VbiDirectoryEnvironment {
    uint64 unknown0;
    uint64 unknown1;
    uint16 unknown2a;
    uint16 unknown2b;
    uint32 unknown2c;
    uint64 unknown3;
    uint64 unknown4;
    uint64 unknown5;
    uint64 unknown6;
    uint64 unknown7;
    uint64 unknown8;
    uint64 unknown9;
    uint64 unknown10;
    uint64 unknown11;
    uint32 unknown12a;
    uint32 unknown13_size;
    uint64 unknown13_va;
    uint64 unknown14;
    uint64 unknown15;
    uint32 unknown16a;
    uint32 unknown17_size;
    uint64 unknown17_va;
    uint32 unknown18a;
    uint32 unknown19_size;
    uint64 unknown19_va;
    uint64 unknown20;
    uint64 kernel_page_table_pa;
    uint64 unknown22;
    uint64 unknown23;
    uint64 unknown24;
    uint32 unknown25a;
    uint32 unknown25b;
    uint64 kernel_loader_block_va;
    uint64 kernel_entrypoint_va;
    uint64 unknown28;
}

struct HypervisorLoaderBlock {
    uint64 unknown_pa[0x300 / 0x8];
}

struct VbiDirectoryLoaderBlock_18 {
    uint64 hv_loader_block_pa;
    uint64 kernel_page_table_pa;
    uint64 kernel_loader_block_va;
}
       
struct VbiDirectoryLoaderBlock {
    uint64 hv_loader_block_pa;
    uint64 kernel_page_table_pa;
    uint64 kernel_loader_block_va;
    uint64 kernel_loader_block_pa;
    uint64 kernel_loader_extension_pa;
};

struct VbiDirectoryUnknown2 {

};

struct ImageRangeEntry {
    uint64 alias_source_pa;
    uint64 alias_dest_pa;
    uint32 size;
    uint32 unk;
}

struct VbiDirectoryImageRanges {
    ImageRangeEntry entries[EOF];
};

struct DebugInfoEntry {
    uint64 unknown;
    uint32 image_name; // PWSTR
    uint32 time_date_stamp;
    uint32 checksum;
    uint32 unknown5;
}

struct VbiDirectoryDebugInfo {
	uint32 version; // mb
    uint32 entries_offset;
    uint32 entry_count; // also image count
    uint32 unknown;
    uint32 unknown2;
    uint32 unknown3;
    uint64 unknown4;
    DebugInfoEntry entries[entry_count];
};

struct VbiDirectoryUnknown5 {
	
};

// Layout: 0x80 entries, then hash_table_entry_count*0x80 entries for l2
struct HashTableEntry {
    uint8 hash[32];
}

struct VbiDirectoryHash {
	uint64 base_physical_unk_pa;
    uint64 base_physical_unk1_pa;
    uint32 unknown_count;
    uint32 hash_table_offset;
    uint32 hash_table_entry_count; // level 1, level 2 size == count * 0x1000
    uint32 unknown5;
};

struct VbiDirectoryUnknown7 {

};

struct MemoryInfo {
    uint64 base_address_pa;
    uint64 page_count;
}

struct VbiDirectoryMemorySize {
	uint64 memory_info_pa; // MemoryInfo
    uint32 address_size_bytes;
    uint32 unknown; // large_page_size mb
    uint32 unknown1;
    uint8 unknown2_b;
    uint64 unknown4;     //uint64 unknown5_pa;
};

struct VbiDirectoryGsCookies {
    uint32 entry_count;
    uint32 unknown : 3;
    uint32 cookie_size : 29;
    uint64 physical_addr_entries[entry_count];
};

enum AslrSectionType : uint8 {
    Executable,
    Unknown1,
    Data,
    Unknown3,
    KernelExecutable
};

struct AslrSection {
    uint32 data_size;
    AslrSectionType type;
    uint8 skip_data_section;
    uint16 page_count;
    uint64 section_base_address_va;
    uint8 data[data_size];
}

union AslrRelocationEntry {
    struct {
        uint64 type : 4;
    };

    struct {
        uint64 base : 48;
        uint64 count : 16;
    } relative;

    struct {
        uint64 type : 4;
        uint64 addend : 60;
    } absolute;

    struct {
        uint64 type : 4;
        uint64 environment_offset : 60;
    } environment_relative;
}

struct AslrHeader {
    uint64 aslr_base_address_va;
    uint64 aslr_pdpt_base_pa;
    uint64 aslr_page_table_base_pa;
    uint32 max_page_count;
    uint32 base_entry_page_count;
    uint64 unk_memory_descriptor_page_count_sub_pa;
    uint64 unk_memory_descriptor_page_count_sub1_pa;
    uint64 unk_memory_descriptor_page_count_add_pa;
}

struct VbiDirectoryAslr {
    uint32 version; // mb
    uint32 entry_count;
	AslrHeader header;
    AslrSection entries[entry_count];
};

struct VbiDirectoryUnknown11 {
	uint64 unknown_target_pa;
    uint64 unknown2_target_pa;
};

struct BootEntropyEntry {
    uint64 pa;
    uint64 size;
}

struct VbiDirectoryBootEntropy {
	BootEntropyEntry entries[EOF];
};

struct Unknown13Entry {
    uint64 value;
    uint64 pa;
}

struct VbiDirectoryUnknown13 {
	uint32 struct_size;
    uint32 unknown1;
    uint32 unknown_count; // same as in hash
    uint32 entry_offset;
    uint64 entry_count;
    uint64 unknown5_pa;
    uint64 unknown6_va;
    uint64 empty_pte_entry_value;
};

struct VbiDirectoryUnknown14 {
    uint64 unknown_pa;
    uint64 unknown2_pa;
}

struct VbiDirectoryLoadOptions {
    uint64 load_options_pa;
    uint64 load_options_va;
}

struct Unknown16Entry {
    uint32 unknown0;
    uint32 unknown1;
    uint32 unknown2;
    uint32 unknown3;
}

struct VbiDirectoryUnknown16 {
    uint32 entry_count;
    uint32 entry_offset;
    uint32 unknown2;
    uint32 unknown3;
}
"""

class AslrRelocationType(IntEnum):
    Relative = 0
    Absolute = 1
    EnvironmentRelative = 2

class AslrSectionType(IntEnum):
    Executable = 0
    DebugExecutable = 1
    Data = 2
    DebugDriver = 3
    KernelImage = 4

class VbiDirectories(IntEnum):
    Environment = 0
    LoaderBlock = 1
    Unknown2 = 2
    ImageRanges = 3
    DebugInfo = 4
    Unknown5 = 5
    Hash = 6
    Unknown7 = 7
    MemorySize = 8
    GsCookies = 9
    Aslr = 10
    Unknown11 = 11
    Unknown12 = 12 # version 2+
    Unknown13 = 13
    Unknown14 = 14
    LoadOptions = 15
    Unknown16 = 16

    MaxDirectory = 17

class VbiVersion(IntEnum):
    Version1 = 1 # Unsupported, relocations are weird
    #Version2 = 2 # Not yet seen
    Version3 = 3 # Tested, also has weird relocations but they were fixable
    #Version4 = 4 # Not yet seen
    Version5 = 5 # Tested
    #Version6 = 6 # Not yet seen
    Version7 = 7 # Tested

    MaxVersion = 8

TYPES = cstruct()
TYPES.load(MEMORY_TYPES, align=False, compiled=True)
assert TYPES.PtEntry.size == 8
assert TYPES.VirtualAddress.size == 8
assert TYPES.PhysicalAddress.size == 8

TYPES.load(LOADER_TYPES, align=True, compiled=True)
assert TYPES.LoaderPerformanceData.size == 0x60
assert TYPES.BootEntropyLdrResult.size == 0x868
assert TYPES.LoaderParameterHypervisorExtension.size == 0x40
assert TYPES.LoaderBugcheckParameters.size == 0x28
assert TYPES.OfflineCrashdumpConfigurationTableV2.size == 0x20
assert TYPES.LoaderHiveRecoveryInfo.size == 0x14
assert TYPES.LoaderResetReason.size == 0x30
assert TYPES.MiniExecutive.size == 0x10
assert TYPES.VsmPerformanceData.size == 0x40
assert TYPES.LoaderFeatureConfigurationInformation.size == 0x48
assert TYPES.EtwBootConfig.size == 0x18
assert TYPES.InstalledMemory.size == 0x10
assert TYPES.CimfsInformation.size == 0x20

TYPES.load(VBI_TYPES, align=True, compiled=True)
assert TYPES.LoaderParameterExtension.size == 0xf20
assert TYPES.LoaderDataTableEntry.size == 0xe0

def pa(addr: int) -> Structure:
    return TYPES.PhysicalAddress(p64(addr))

def va(addr: int) -> Structure:
    return TYPES.VirtualAddress(p64(addr))

def pte(val: int) -> Structure:
    return TYPES.PtEntry(p64(val))