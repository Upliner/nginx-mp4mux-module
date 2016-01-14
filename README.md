### Cache settings

Cache settings must be placed to the `http` context and shared for all mp4mux locations

#### mp4mux_cache_size
Cache size in bytes, default: 128m

#### mp4mux_cache_maxskip
Maximum number of locked entries allowed to skip in fixed cache, default: 3

## TODO
#### mp4mux_cache_type
* **fixed**: use nginx shared memory feature
* **devshm**: use posix shm_open() and /dev/shm/
* **sysv**: use SysV shmget() and shmat()

#### mp4mux_cache_hash_size
Size of the hashtable in bytes, default 16k
