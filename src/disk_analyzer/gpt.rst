GUID Partition Table
-------------------------------------------------------------------------------

Reminder: LBA == logical block address, sequential index into 512-byte sectors

LBA0 = Protective MBR
    + First stage bootloader
    + Single partition, 0xEE covers entire drive, denotes GPT presence

LBA1 = Primary GPT Header
    + [8] Signature: "EFI PART"
    + [4] Revision: 00 00 01 00 --> GPT Version 1.0
    + [4] Header Size: usually 92 bytes --> 5c 00 00 00
    + [4] CRC32 of header
    + [4] Reserved,0
    + [8] Current LBA (location of this header)
    + [8] Backup LBA
    + [8] First usable LBA
    + [8] Last usable LBA
    + [16] Disk GUID (UUID)
    + [4] Number of partition entries
    + [4] Size of partition entry (PTE)
    + * Reserved, should be 0 for rest of block (420 bytes)
