Modern Ubuntu Disk Layout
-------------------------------------------------------------------------------

- LBA 0 -- normal MBR
- Partition Entry 0 -- 243 MiB ext2 Boot Partition [sectors 0x800 to 0x79800]
- Partition Entry 1 -- Rest of Drive, 'Extended' Type [start 0x7a7fe]
    - EBR Record
        - Partition Entry 0 -- Rest, 'Linux LVM' type, [start 0x2]
        - Partition Entry 1 -- Unused (no chain)
        - Partition Entry 2 -- Unused
        - Partition Entry 3 -- Unused
- Partition Entry 2 -- Unused
- Partition Entry 3 -- Unused
