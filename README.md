# gammaray

gammaray is a system implementing disk-based introspection for virtual
machines.  It thus far works with VMs that have disks virtualized via QEMU;
however, this limitation is only due to the scarcity of developer time.
Conceptually, and practically, gammaray can perform introspection with any
source of raw disk writes.  The instructions below assume an Ubuntu 12.04 LTS
host, although they should be similar for most distributions of Linux.

## Dependencies

The following libraries are needed to build and execute gammaray:

1. hiredis [BSD 3-clause] - the Redis client-side library

   ```bash
   sudo apt-get install libhiredis-dev libhiredis0.10
   ```
2. bson [Optional, BSD 3-clause] - Python BSON library
3. redis-py [Optional, MIT] - Python hiredis wrapper

The Python libraries are optional if you want to write or execute Python
monitors consuming gammaray's publish-subscribe stream of file-level updates.

In addition to `libhiredis`, gammaray requires a slightly modified version of
QEMU.  Clone the QEMU repository, apply a patch for gammaray support, and then
compile a gammaray-friendly QEMU.

1. git clone...
2. git apply...
3. enjoy!

## Installation Procedure

1. Ensure all dependencies are installed already
2. git clone gammaray's source tree
3. Bootstrap your source tree
4. Run configure
5. Run make
6. [Optional] Run make install (if you want)

All binaries will now be built and placed in the bin folder at the top-level
directory of the project.

## Description of Components

gammaray is organized as a set of tools, described below:

1. `gray-crawler` - used to index a disk in preparation for introspection
    * This tool is usually used offline, although it can be used online as well

2. `gray-ndb-queuer` - used to asynchronously queue writes for analysis
    * This tool interfaces with a stream of writes, soon-to-be an NBD endpoint

3. `gray-inferencer` - used to analyze queued writes and perform introspection
    * This tool loads and maintains metadata in-sync with a live disk

4. `gray-fs` - used to produce a FUSE file system view of the in-sync metadata
    * This tool provides a read-only FS without mounting the real guest FS

## High-Level Operation

The exact steps are enumerated below, but at a high level you must crawl the
disk you wish to introspect, load metadata from that crawl for run-time
introspection, and attach a copy of the write stream to that disk at run-time
to the inferencing backend.  Currently, this is coordinated via a named pipe
and Redis.  In the future, the named pipe is being replaced by NBD.

1. Crawl the disk that you wish to introspect using `gray-crawler`
2. Setup a named pipe to receive raw disk writes to the `gray-ndb-queuer`
3. Run the `gray-ndb-queuer` and let it read from the named pipe
4. Run `gray-inferencer` and wait for it to load metadata from `gray-crawler`
5. Run QEMU with this disk redirecting stderr output to the named pipe 

## Example Creation of gammaray-Supported Disk Layout

If you're sufficiently confident with the installer of your OS of choice, feel
free to skip the steps below.  Otherwise, it might be easier to setup a known
good partition configuration with a host system and then install the guest OS
into the pre-existing partition.

1. Use dd or another suitable command to preallocate the raw disk image

   ```bash
   dd of=disk.raw seek=$((1024*1024*1024*5)) count=0 bs=1
   ```

2. Create a partition table

   ```bash
   parted -s disk.raw mklabel msdos
   ```    

3. Create a single primary partition taking up the entire image

   ```bash
   parted -s disk.raw mkpart primary ext4 1 $((1024*5))
   ```

4. Make the partition visible to your host as a block device

   ```bash
   sudo kpartx -av disk.raw
   ```

5. Format the partition as ext4 [replace loop0 with output from kpartx command]

   ```bash
   sudo mkfs.ext4 /dev/mapper/loop0p1
   ```

6. Remove the visible partition and block device from your host

   ```bash
   sudo kpartx -dv disk.raw
   ```

7. Boot the instance with install media and the new drive attached

   ```bash
  qemu-system-x86_64 disk.raw -cpu kvm64 -cdrom ubuntu-12.04.2-server-amd64.iso
   ```

8. Using `Manual Partitioning` at the disk setup phase, select the first
   partition to be used as `ext4` and `mount point '/'`

9. Then just finish partitioning and continue with the installation procedure

## Current Limitations

1. Supported File Systems
    * ext4
    * NTFS

2. Supported VMMs
    * KVM/QEMU

3. Supported Number of Disks
    * Single attached disk

4. Supported Number of File Systems
    * Single introspected file system

5. Supported Disk Formats
    * raw
