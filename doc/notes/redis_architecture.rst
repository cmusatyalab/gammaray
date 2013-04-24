Redis Backed KV Store
-------------------------------------------------------------------------------

- Redis will be used to store sector writes until we know what they are

  - Unknown writes get placed into the store by being broken up into 512 byte
    constituent sectors

    Key: (uint64_t) sector number
    Value: (bytes[512]) sector data

- Set TTL to 5 minutes for each sector write

- Our C code runs ahead with the next write
    
    + If we ID an associated file or metadata
        (0) Pull data from Redis (delete if easy, otherwise timeout)
        (1) Emit BSON message in Pub-Sub Redis channel

Redis Backed Pub-Sub
-------------------------------------------------------------------------------

- We emit on channels of the form:
    'machine:vm:path'

- These channels contain metadata and data updates in BSON format
