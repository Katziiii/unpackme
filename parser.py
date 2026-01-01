import sys
import struct

BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"

BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024
VENDOR_BOOT_ARGS_SIZE = 2048

DEFAULT_KERNEL_OFFSET = 0x00008000


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def parse_boot(path):
    with open(path, "rb") as f:
        hdr = f.read(8192)

    if len(hdr) < 48 or hdr[:8] != BOOT_MAGIC:
        raise RuntimeError("Not a valid boot.img")

    header_version = u32(hdr, 40)
    page_size = u32(hdr, 36)

    # kernel/ramdisk addresses and sizes (v0..v2 header fields exist here; for v3+ kernel load addresses may not be meaningful)
    kernel_size = u32(hdr, 8)
    kernel_addr = u32(hdr, 12)
    ramdisk_size = u32(hdr, 16)
    ramdisk_addr = u32(hdr, 20)
    tags_addr = u32(hdr, 32)

    # cmdline extraction: for header <3 the cmdline field is split; for v3+ it's combined.
    if header_version < 3:
        cmdline_size = BOOT_ARGS_SIZE  # we keep the kernel cmdline part
    else:
        cmdline_size = BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE

    cmdline_off = 48
    cmdline = hdr[cmdline_off:cmdline_off + cmdline_size].split(b'\x00', 1)[0].decode(errors="ignore")

    print(f"BOARD_BOOT_HEADER_VERSION := {header_version}")
    print(f"BOARD_KERNEL_CMDLINE := {cmdline}")

    if header_version < 3:
        base = kernel_addr - DEFAULT_KERNEL_OFFSET
        print(f"BOARD_PAGE_SIZE := {page_size}")
        print(f"BOARD_KERNEL_BASE := 0x{base:08x}")
        print(f"BOARD_KERNEL_OFFSET := 0x{(kernel_addr - base):08x}")
        print(f"BOARD_RAMDISK_OFFSET := 0x{(ramdisk_addr - base):08x}")
        print(f"BOARD_TAGS_OFFSET := 0x{(tags_addr - base):08x}")
        # DTB offset for v1/v2 stored later in header; we don't try to infer here beyond tags
    else:
        # For header v3+, offsets are typically not used by bootloader.
        # Still print page size so BoardConfig can include it if needed.
        print(f"BOARD_PAGE_SIZE := {page_size}")


def parse_vendor_boot(path):
    with open(path, "rb") as f:
        hdr = f.read(8192)

    if len(hdr) < 64 or hdr[:8] != VENDOR_BOOT_MAGIC:
        raise RuntimeError("Not a valid vendor_boot.img")

    header_version = u32(hdr, 8)
    page_size = u32(hdr, 12)

    # kernel/ramdisk physical addresses (absolute)
    kernel_addr = u32(hdr, 16)
    ramdisk_addr = u32(hdr, 20)

    # vendor_cmdline starts at offset 28 (after magic + header_version + pagesize + kernel + ramdisk + ramdisk_size)
    vendor_cmdline_off = 28
    vendor_cmdline = hdr[vendor_cmdline_off:vendor_cmdline_off + VENDOR_BOOT_ARGS_SIZE].split(b'\x00', 1)[0].decode(errors="ignore")

    tags_addr_off = vendor_cmdline_off + VENDOR_BOOT_ARGS_SIZE
    tags_addr = u32(hdr, tags_addr_off)

    # dtb addr is after tags (4), board name (16), header_size (4), dtb_size (4) => advance by 4+16+4+4
    dtb_addr_off = tags_addr_off + 4 + 16 + 4 + 4
    dtb_addr = u64(hdr, dtb_addr_off)

    # Reconstruct base using the Android convention (kernel_addr - 0x8000)
    base = kernel_addr - DEFAULT_KERNEL_OFFSET

    kernel_offset = kernel_addr - base
    ramdisk_offset = ramdisk_addr - base
    tags_offset = tags_addr - base
    dtb_offset = dtb_addr - base

    # Print only the BoardConfig-style variables (no vendor_* lines)
    print(f"BOARD_KERNEL_BASE := 0x{base:08x}")
    print(f"BOARD_KERNEL_OFFSET := 0x{kernel_offset:08x}")
    print(f"BOARD_RAMDISK_OFFSET := 0x{ramdisk_offset:08x}")
    print(f"BOARD_TAGS_OFFSET := 0x{tags_offset:08x}")
    print(f"BOARD_DTB_OFFSET := 0x{dtb_offset:08x}")
    print(f"BOARD_PAGE_SIZE := {page_size}")
    print(f"BOARD_BOOT_HEADER_VERSION := {header_version}")

    # Optionally emit BOARD_VENDOR_CMDLINE if present
    if vendor_cmdline:
        print(f"BOARD_VENDOR_CMDLINE := {vendor_cmdline}")


def main():
    if len(sys.argv) != 2:
        print("Usage: parser.py <boot.img | recovery.img | vendor_boot.img>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
    except Exception as e:
        print(f"Error opening file: {e}")
        sys.exit(2)

    try:
        if magic == BOOT_MAGIC:
            parse_boot(path)
        elif magic == VENDOR_BOOT_MAGIC:
            parse_vendor_boot(path)
        else:
            print("Unknown image type (magic mismatch). Provide boot.img or vendor_boot.img")
            sys.exit(3)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(4)


if __name__ == "__main__":
    main()
