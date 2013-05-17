# gammaray

gammaray is a system implementing disk-based
[introspection](http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.11.8367)
for virtual machines.  It thus far works with VMs that have disks virtualized
via [QEMU](http://www.qemu.org); however, this limitation is only due to the
scarcity of developer time.  Conceptually, and practically, gammaray can
perform introspection with any source of raw disk writes.  The instructions
below assume an [Ubuntu 12.04 LTS](http://releases.ubuntu.com/precise/) host,
although they should be similar for most distributions of Linux.

## Quickstart

1. Follow the non-optional [dependencies](#dependencies) instructions

2. Follow the [example](#example-creation-of-gammaray-supported-disk-layout)
   virtul disk creation instructions

3. Follow the [installation procedure](#installing-gammaray) for gammaray

4. Follow the [instructions](#gammaray-pipeline) for running the gammaray
   pipeline

## License

All source code, documentation, and related artifacts associated with the
gammaray open source project are licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

A copy of this license is reproduced in the [LICENSE](LICENSE) file, and the
licenses of dependencies and included code are enumerated in the
[NOTICE](NOTICE) file.


## Dependencies

The following libraries are needed to build and execute gammaray (most
developers can skip the Python libraries):

1. [hiredis](https://github.com/redis/hiredis) [BSD 3-clause] - the Redis
   client-side library

   ```bash
   sudo apt-get install libhiredis-dev libhiredis0.10
   ```

2. [bson](https://pypi.python.org/pypi/bson/0.3.2) [Optional, BSD 3-clause] -
   Python BSON library

3. [redis-py](https://github.com/andymccurdy/redis-py) [Optional, MIT] - Python
   hiredis wrapper

The Python libraries are optional if you want to write or execute Python
monitors consuming gammaray's publish-subscribe stream of file-level updates.

In addition to `libhiredis`, gammaray requires a slightly modified version of
QEMU.  Clone the QEMU repository, apply a patch for gammaray support, and then
compile a gammaray-friendly QEMU.

1. Get the official QEMU source tree
 
   ```bash
   git clone git://git.qemu-project.org/qemu.git
   ```

2. Checkout a specific tagged commit to apply our patch cleanly
   
   ```bash
   git checkout v1.4.0
   ```

3. Get our patch

   ```bash
   git clone https://gist.github.com/5ceeccdf6107222b256a.git
   ```  

4. Apply the patch to your checked out QEMU tree

   ```bash
   git apply binary_tracing_block_qemu_1-4-0.patch
   ```

5. Configure QEMU, remember to change the prefix as needed

   ```bash
   ./configure \
    --enable-system \
    --disable-user \
    --enable-kvm \
    --enable-trace-backend=stderr \
    --target-list='i386-softmmu i386-linux-user x86_64-linux-user x86_64-softmmu' \
    --prefix=/home/wolf/qemu_bin \
    --static
   ```
   
6. Make, and make install QEMU.

   ```bash
   make
   make install
   ```

7. QEMU binaries with the patch compiled in should be within the `prefix`
   folder, specifically inside the `bin` subfolder.

## Installing gammaray

1. Ensure all dependencies are installed already
2. git clone gammaray's source tree

   ```bash
   git clone https://github.com/cmusatyalab/gammaray.git
   ```

3. Bootstrap your source tree

   ```bash
   ./bootstrap.sh
   ```

4. Run configure

   ```bash
   ./configure
   ```

5. Run make

   ```bash
   make
   ```

6. [Optional] Run make install (if you want)

   ```bash
   make install
   ```

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

## gammaray Pipeline 

The exact steps are enumerated below, but at a high level you must crawl the
disk you wish to introspect, load metadata from that crawl for run-time
introspection, and attach a copy of the write stream to that disk at run-time
to the inferencing backend.  Currently, this is coordinated via a named pipe
and Redis.  In the future, the named pipe is being replaced by NBD.  None of
the tools auto-daemonize as of this writing.

1. Crawl the disk that you wish to introspect using `gray-crawler`

   ```bash
   gray-crawler disk.raw disk.bson
   ```

2. Setup a named pipe to receive raw disk writes to the `gray-ndb-queuer`

   ```bash
   mkfifo disk.fifo
   ```

3. Run the `gray-ndb-queuer` and let it read from the named pipe

   ```bash
   gray-ndb-queuer disk.fifo 4 1>queuer.log 2>queuer.error.log &
   ```

4. Run `gray-inferencer` and wait for it to load metadata from `gray-crawler`

   ```bash
   gray-inferencer disk.bson 4 disk_test_instance &
   ```
 
5. Run QEMU with this disk redirecting stderr output to the named pipe 

   ```bash
   /path/to/custom/qemu-system-x86_64 \
    -enable-kvm \
    -cpu kvm64 \
    -smp cores=1,threads=1,sockets=1 \
    -drive file=disk.raw,if=virtio,aio=native \
    -m 1024 \
    -display vnc=127.0.0.1:1 \
    -trace events=events \
    -redir tcp:2222::22 2> disk.fifo &
   ```

   Remember to use the specially built QEMU when installing dependencies (ie
   replace the path in the above command).  Also, ensure you have an `events`
   file that turns on tracing for the event of interest: `bdrv_write`.  The
   `events` file's contents should have only that event name on a single
   line by itself (tracing multiple events will mangle the binary tracing
   needed for disk introspection).

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

8. Using `Manual Partitioning` at the disk setup stage, select the first
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
