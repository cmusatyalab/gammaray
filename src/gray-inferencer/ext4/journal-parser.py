#!/usr/bin/env python
# vim:set nospell:

from LogRecord import LogRecord



from struct import unpack
from sys import argv
from uuid import UUID


SECTOR_SIZE = 512

# 0x0 __be32  h_magic jbd2 magic number, 0xC03B3998.
# 0x4 __be32  h_blocktype Description of what this block contains. One of:
#         1   Descriptor. This block precedes a series of data blocks that were
#             written through the journal during a transaction.
#         2   Block commit record. This block signifies the completion of a
#             transaction.
#         3   Journal superblock, v1.
#         4   Journal superblock, v2.
#         5   Block revocation records. This speeds up recovery by enabling the
#             journal to skip writing blocks that were subsequently rewritten.
# 0x8 __be32  h_sequence  The transaction ID that goes with this block.
class JBD2BlockHeader(object):
    MAGIC = 0xC03B3998

    BLOCKTYPE = { 0x1: 'Descriptor',
                  0x2: 'Commit',
                  0x3: 'Superblockv1',
                  0x4: 'Superblockv2',
                  0x5: 'Revocation'
                }

    def __init__(self, data):
        self.h_magic, \
        self.h_blocktype, \
        self.h_sequence = unpack('>III', data)

    def __str__(self):
        retstr  = '{ .h_magic = 0x%x, \n'
        retstr += '  .h_blocktype = %s\n'
        retstr += '  .h_sequence = 0x%x }'
        return retstr % (self.h_magic,
                         JBD2BlockHeader.BLOCKTYPE[self.h_blocktype],
                         self.h_sequence)

# 0x0     journal_header_t (12 bytes)     s_header        Common header identifying this as a superblock.
# Static information describing the journal.
# 0xC     __be32  s_blocksize     Journal device block size.
# 0x10    __be32  s_maxlen        Total number of blocks in this journal.
# 0x14    __be32  s_first First block of log information.
# Dynamic information describing the current state of the log.
# 0x18    __be32  s_sequence      First commit ID expected in log.
# 0x1C    __be32  s_start Block number of the start of log. Contrary to the comments, this field being zero does not imply that the journal is clean!
# 0x20    __be32  s_errno Error value, as set by jbd2_journal_abort().
# The remaining fields are only valid in a version 2 superblock.
# 0x24    __be32  s_feature_compat;       Compatible feature set. Any of:
# 0x1     Journal maintains checksums on the data blocks. (JBD2_FEATURE_COMPAT_CHECKSUM)
# 0x28    __be32  s_feature_incompat      Incompatible feature set. Any of:
# 0x1     Journal has block revocation records. (JBD2_FEATURE_INCOMPAT_REVOKE)
# 0x2     Journal can deal with 64-bit block numbers. (JBD2_FEATURE_INCOMPAT_64BIT)
# 0x4     Journal commits asynchronously. (JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)
# 0x8     This journal uses v2 of the checksum on-disk format. Each journal metadata block gets its own checksum, and the block tags in the descriptor table contain checksums for each of the data blocks in the journal. (JBD2_FEATURE_INCOMPAT_CSUM_V2)
# 0x10    This journal uses v3 of the checksum on-disk format. This is the same as v2, but the journal block tag size is fixed regardless of the size of block numbers. (JBD2_FEATURE_INCOMPAT_CSUM_V3)
# 0x2C    __be32  s_feature_ro_compat     Read-only compatible feature set. There aren't any of these currently.
# 0x30    __u8    s_uuid[16]      128-bit uuid for journal. This is compared against the copy in the ext4 super block at mount time.
# 0x40    __be32  s_nr_users      Number of file systems sharing this journal.
# 0x44    __be32  s_dynsuper      Location of dynamic super block copy. (Not used?)
# 0x48    __be32  s_max_transaction       Limit of journal blocks per transaction. (Not used?)
# 0x4C    __be32  s_max_trans_data        Limit of data blocks per transaction. (Not used?)
# 0x50    __u8    s_checksum_type Checksum algorithm used for the journal. 1 = crc32, 2 = md5, 3 = sha1, 4 = crc32c. 1 or 4 are the most likely choices.
# 0x51    __u8[3] s_padding2      
# 0x54    __u32   s_padding[42]   
# 0xFC    __be32  s_checksum      Checksum of the entire superblock, with this field set to zero.
# 0x100   __u8    s_users[16*48]  ids of all file systems sharing the log. e2fsprogs/Linux don't allow shared external journals, but I imagine Lustre (or ocfs2?), which use the jbd2 code, might.
class JBD2SuperBlock(object):
    JBD2_FEATURE_COMPAT_CHECKSUM = 0x1

    JBD2_FEATURE_INCOMPAT_REVOKE        = 0x1
    JBD2_FEATURE_INCOMPAT_64BIT         = 0x2
    JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT  = 0x4
    JBD2_FEATURE_INCOMPAT_CSUM_V2       = 0x8
    JBD2_FEATURE_INCOMPAT_CSUM_V3       = 0x10

    CHECKSUM =  { 1: 'crc32',
                  2: 'md5',
                  3: 'sha1',
                  4: 'crc32c'
                }

    def __init__(self, data):
        self.s_blocksize, \
        self.s_maxlen, \
        self.s_first, \
        self.s_sequence, \
        self.s_start, \
        self.s_errno, \
        self.s_feature_compat, \
        self.s_feature_incompat, \
        self.s_feature_ro_compat, \
        self.s_uuid, \
        self.s_nr_users, \
        self.s_dynsuper, \
        self.s_max_transaction, \
        self.s_max_trans_data, \
        self.s_checksum_type, \
        self.s_padding2, \
        self.s_padding, \
        self.s_checksum, \
        self.s_users = \
        unpack('>9I16s4IB3s168sI768s', data[:1012])

    def __str__(self):
        retstr  = '-- JBD2 Superblock --\n'
        retstr += '\ts_blocksize\t\t=\t%d\n' % (self.s_blocksize)
        retstr += '\ts_maxlen\t\t=\t%d (%d MiB)\n' % (self.s_maxlen,
                                                      self.s_blocksize *
                                                      self.s_maxlen /
                                                      1024 ** 2)
        retstr += '\ts_feature_compat\t=\t0x%0.8x\n' % (self.s_feature_compat)

        if self.s_feature_compat & \
           JBD2SuperBlock.JBD2_FEATURE_COMPAT_CHECKSUM:
            retstr += '\tJBD2_FEATURE_COMPAT_CHECKSUM is set.\n'

        retstr += '\ts_feature_incompat\t=\t0x%0.8x\n' % \
                  (self.s_feature_incompat)

        if self.s_feature_incompat & \
           JBD2SuperBlock.JBD2_FEATURE_INCOMPAT_REVOKE:
            retstr += '\tJBD2_FEATURE_INCOMPAT_REVOCATION is set.\n'
        if self.s_feature_incompat & \
           JBD2SuperBlock.JBD2_FEATURE_INCOMPAT_64BIT:
            retstr += '\tJBD2_FEATURE_INCOMPAT_64BIT is set.\n'
        if self.s_feature_incompat & \
           JBD2SuperBlock.JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT:
            retstr += '\tJBD2_FEATURE_INCOMPAT_ASYNC_COMMIT is set.\n'
        if self.s_feature_incompat & \
           JBD2SuperBlock.JBD2_FEATURE_INCOMPAT_CSUM_V2:
            retstr += '\tJBD2_FEATURE_COMPAT_CSUM_V2 is set.\n'
        if self.s_feature_incompat & \
           JBD2SuperBlock.JBD2_FEATURE_INCOMPAT_CSUM_V3:
            retstr += '\tJBD2_FEATURE_COMPAT_CSUM_V3 is set.\n'

        retstr += '\tself.s_uuid\t\t=\t%s\n' % UUID(bytes=self.s_uuid)
        retstr += '\tself.s_nr_users\t\t=\t%d\n' % (self.s_nr_users)
        retstr += '\tself.s_max_transaction\t=\t%d\n' % \
                  (self.s_max_transaction)
        retstr += '\tself.s_max_trans_data\t=\t%d\n' % \
                  (self.s_max_trans_data)

        if self.s_checksum_type != 0x0:
            retstr += '\tself.s_checksum_type\t=\t%s\n' % \
                      (JBD2SuperBlock.CHECKSUM[self.s_checksum_type])

        for i in xrange(self.s_nr_users):
            retstr += '\tself.users[%d]\t\t=\t%s\n' % \
                      (i, UUID(bytes=self.s_users[16*i:16+16*i]))

        retstr += '-- End JBD2 Superblock --\n'

        return retstr


class JBD2RevocationBlock(object):
    pass

# 0x0     journal_header_s        (open coded)    Common block header.
# 0xC     unsigned char   h_chksum_type   The type of checksum to use to verify the integrity of the data blocks in the transaction. One of:
# 1       CRC32
# 2       MD5
# 3       SHA1
# 4       CRC32C
# 0xD     unsigned char   h_chksum_size   The number of bytes used by the checksum. Most likely 4.
# 0xE     unsigned char   h_padding[2]    
# 0x10    __be32  h_chksum[JBD2_CHECKSUM_BYTES]   32 bytes of space to store checksums. If JBD2_FEATURE_INCOMPAT_CSUM_V2 or JBD2_FEATURE_INCOMPAT_CSUM_V3 are set, the first __be32 is the checksum of the journal UUID and the entire commit block, with this field zeroed. If JBD2_FEATURE_COMPAT_CHECKSUM is set, the first __be32 is the crc32 of all the blocks already written to the transaction.
# 0x30    __be64  h_commit_sec    The time that the transaction was committed, in seconds since the epoch.
# 0x38    __be32  h_commit_nsec   Nanoseconds component of the above timestamp.
class JBD2CommitBlock(object):
    def __init__(self, data):
        self.h_chksum_type, \
        self.h_chksum_size, \
        self.h_padding, \
        self.h_chksum, \
        self.h_commit_sec, \
        self.h_commit_nsec = \
        unpack('>BB2s32sQI', data[:48])

    def __str__(self):
        retstr  = '-- JBD2CommitBlock --\n'
        retstr += '\th_chksum_type\t=\t%d\n' % self.h_chksum_type
        retstr += '\th_chksum_size\t=\t%d\n' % self.h_chksum_size
        retstr += '\th_chksum\t=\t%r\n' % self.h_chksum
        retstr += '\th_commit_sec\t=\t%d\n' % self.h_commit_sec
        retstr += '\th_commit_nsec\t=\t%d\n' % self.h_commit_nsec
        return retstr

# 0x0     journal_header_t        (open coded)    Common block header.
# 0xC     struct journal_block_tag_s      open coded array[]      Enough tags either to fill up the block or to describe all the data blocks that follow this descriptor block.
# Journal block tags have any of the following formats, depending on which journal feature and block tag flags are set.
# If JBD2_FEATURE_INCOMPAT_CSUM_V3 is set, the journal block tag is defined as struct journal_block_tag3_s, which looks like the following. The size is 16 or 32 bytes.
# Offset  Type    Name    Descriptor
# 0x0     __be32  t_blocknr       Lower 32-bits of the location of where the corresponding data block should end up on disk.
# 0x4     __be32  t_flags Flags that go with the descriptor. Any of:
# 0x1     On-disk block is escaped. The first four bytes of the data block just happened to match the jbd2 magic number.
# 0x2     This block has the same UUID as previous, therefore the UUID field is omitted.
# 0x4     The data block was deleted by the transaction. (Not used?)
# 0x8     This is the last tag in this descriptor block.
# 0x8     __be32  t_blocknr_high  Upper 32-bits of the location of where the corresponding data block should end up on disk. This is zero if JBD2_FEATURE_INCOMPAT_64BIT is not enabled.
# 0xC     __be32  t_checksum      Checksum of the journal UUID, the sequence number, and the data block.
# This field appears to be open coded. It always comes at the end of the tag, after t_checksum. This field is not present if the "same UUID" flag is set.
# 0x8 or 0xC      char    uuid[16]        A UUID to go with this tag. This field appears to be copied from the j_uuid field in struct journal_s, but only tune2fs touches that field.
# If JBD2_FEATURE_INCOMPAT_CSUM_V3 is NOT set, the journal block tag is defined as struct journal_block_tag_s, which looks like the following. The size is 8, 12, 24, or 28 bytes:
# Offset  Type    Name    Descriptor
# 0x0     __be32  t_blocknr       Lower 32-bits of the location of where the corresponding data block should end up on disk.
# 0x4     __be16  t_checksum      Checksum of the journal UUID, the sequence number, and the data block. Note that only the lower 16 bits are stored.
# 0x6     __be16  t_flags Flags that go with the descriptor. Any of:
# 0x1     On-disk block is escaped. The first four bytes of the data block just happened to match the jbd2 magic number.
# 0x2     This block has the same UUID as previous, therefore the UUID field is omitted.
# 0x4     The data block was deleted by the transaction. (Not used?)
# 0x8     This is the last tag in this descriptor block.
# This next field is only present if the super block indicates support for 64-bit block numbers.
# 0x8     __be32  t_blocknr_high  Upper 32-bits of the location of where the corresponding data block should end up on disk.
# This field appears to be open coded. It always comes at the end of the tag, after t_flags or t_blocknr_high. This field is not present if the "same UUID" flag is set.
# 0x8 or 0xC      char    uuid[16]        A UUID to go with this tag. This field appears to be copied from the j_uuid field in struct journal_s, but only tune2fs touches that field.
# If JBD2_FEATURE_INCOMPAT_CSUM_V2 or JBD2_FEATURE_INCOMPAT_CSUM_V3 are set, the end of the block is a struct jbd2_journal_block_tail, which looks like this:
# Offset  Type    Name    Descriptor
# 0x0     __be32  t_checksum      Checksum of the journal UUID + the descriptor block, with this field set to zero.
class JBD2DescriptorBlock(object):
    def __init__(self, data):
        self.journal_block_tag_s = \
                [tag for tag in JBD2DescriptorBlock.ReadBlockTags(data)]

    @staticmethod
    def ReadBlockTags(data):
        pos = 0
        tag = None
        while pos < len(data) and (tag is None or not tag.t_flags & 0x8):
            tag = JBD2BlockTag(data[pos:])
            pos += tag.size
            yield tag

    def tagGenerator(self):
        for tag in self.journal_block_tag_s:
            yield tag

    def __str__(self):
        retstr = '-- JBD2 Descriptor Block --\n'
        
        for tag in self.journal_block_tag_s:
            retstr += str(tag)

        return retstr

class JBD2BlockTag(object):
    def __init__(self, data):
        self.t_blocknr, \
        self.t_checksum, \
        self.t_flags = unpack('>IHH', data[0:8])
        self.t_uuid = None
        self.size = 8

        if not self.t_flags & 0x2:
            self.t_uuid = UUID(bytes=unpack('>16s', data[8:24])[0])
            self.size = 24

    def __str__(self):
        retstr  = '\t-- JBD2 Tag --\n'
        retstr += '\t\tt_blocknr\t=\t%d\n' % self.t_blocknr
        retstr += '\t\tt_checksum\t=\t%d\n' % self.t_checksum
        retstr += '\t\tt_flags\t\t=\t0x%0.8x\n' % self.t_flags
        if self.t_uuid is not None:
            retstr += '\t\tt_uuid\t=\t%s\n' % self.t_uuid
        return retstr

if __name__ == '__main__':
    fname = argv[1]

    with open(fname, 'rb') as f:
        prevts = 0
        current_tags = None
        superblock = None

        for log in LogRecord.LogRecordGenerator(f.read()):
            if log.type == 'data':
                print log
                
                hdr = JBD2BlockHeader(log.write[:12])

                if hdr.h_magic == JBD2BlockHeader.MAGIC:
                    print hdr
                    data = log.write[12:]
                    if hdr.h_blocktype == 0x1:
                        print '-- Descriptor Block --'
                        descriptor = JBD2DescriptorBlock(data)
                        current_tags = descriptor.tagGenerator()
                        print descriptor
                    elif hdr.h_blocktype == 0x2:
                        print '-- Commit Block --'
                        commit = JBD2CommitBlock(data)
                        try:
                            current_tags.next()
                            raise Exception('Did not process all tags!')
                        except StopIteration:
                            print '\tFinished Processing all tags.'
                        print commit
                    elif hdr.h_blocktype == 0x3:
                        print '-- Superblock v1 --'
                    elif hdr.h_blocktype == 0x4:
                        print '-- Superblock v2 --'
                        superblock = JBD2SuperBlock(data)
                        print superblock
                    elif hdr.h_blocktype == 0x5:
                        print '-- Revocation Block --'
                        exit()
                    else:
                        raise Exception('Unknown JBD2 Block Type.')
                else:
                    tag = current_tags.next()
                    if tag.t_flags & 0x1: data[0:4] = (0xc0, 0x3b, 0x39, 0x98)
                    sector = tag.t_blocknr
                    sector *= superblock.s_blocksize
                    sector /= SECTOR_SIZE
                    print 'Data Write to Sector: %d\n' % (sector)

                if prevts == 0: prevts = int(log.timestamp)
                print int(log.timestamp) - prevts
                prevts = int(log.timestamp)
            else:
                print log # metadata
