package net.lapisphilosophorum.lapisnet.storage

import io.ipfs.multihash.Multihash
import org.peergos.protocol.dht.RecordStore
import org.peergos.protocol.ipns.IpnsRecord
import java.util.Collections
import java.util.Optional

/**
 * Bounded, in-memory [RecordStore]. Nabu's own `org.peergos.protocol.dht.RamRecordStore` is an
 * uncapped `HashMap`, but `KademliaEngine.receiveRequest` (Nabu's own protocol handler, not this
 * project's code) hands any connected peer's signed IPNS `PUT_VALUE` record straight to whatever
 * `RecordStore` was supplied - reachable regardless of whether this project's own API ever calls
 * `publishIpnsValue`, with no other rate limit or size cap on Nabu's side. An uncapped record
 * store lets a peer grow this node's heap without bound simply by publishing records for
 * arbitrarily many distinct keys. Mirrors the LRU-eviction approach
 * `org.peergos.protocol.dht.RamProviderStore` already applies to its own sibling store.
 */
internal class BoundedRecordStore(
    maxSize: Int,
) : RecordStore {
    private val records =
        Collections.synchronizedMap(
            object : LinkedHashMap<Multihash, IpnsRecord>(16, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Multihash, IpnsRecord>): Boolean =
                    size > maxSize
            },
        )

    override fun put(
        publisher: Multihash,
        record: IpnsRecord,
    ) {
        records[publisher] = record
    }

    override fun get(publisher: Multihash): Optional<IpnsRecord> = Optional.ofNullable(records[publisher])

    override fun remove(publisher: Multihash) {
        records.remove(publisher)
    }

    override fun close() {}
}
