package net.lapisphilosophorum.lapisnet.networking

import io.libp2p.core.PeerId
import io.libp2p.core.crypto.PrivKey
import io.libp2p.crypto.keys.unmarshalEd25519PrivateKey
import net.lapisphilosophorum.lapisnet.identity.DualKeyIdentity

/**
 * Derives this identity's libp2p signing key ([PrivKey]) from its Ed25519 keypair. Internal:
 * only [LapisNode] needs the jvm-libp2p-wrapped signing key - callers that just want to
 * identify, compare, or log a peer should use [deriveLibp2pPeerId] instead. Note this only gates
 * the wrapped [PrivKey] object - `lapis-net-identity`'s own
 * [net.lapisphilosophorum.lapisnet.identity.Ed25519PrivateKey.seed] getter is public and already
 * exposes the same raw signing-key bytes to any module depending on `lapis-net-identity`; this
 * function does not add confidentiality beyond what that module already provides.
 *
 * The raw 32-byte seed [net.lapisphilosophorum.lapisnet.identity.Ed25519PrivateKey.seed] stores
 * is exactly the byte layout jvm-libp2p's `unmarshalEd25519PrivateKey` expects - no adapter or
 * re-encoding needed.
 */
internal fun DualKeyIdentity.deriveLibp2pPrivKey(): PrivKey = unmarshalEd25519PrivateKey(ed25519KeyPair.privateKey.seed)

/**
 * Deterministically derives this identity's libp2p [PeerId] - the same [DualKeyIdentity] always
 * produces the same [PeerId], since it is a pure function of the Ed25519 key material. The
 * public key is derived from the private key (not read from the separately-stored public key
 * bytes), so a corrupted keystore that somehow desynced its stored public key from its private
 * key can never produce a [PeerId] the node can't actually sign with.
 */
fun DualKeyIdentity.deriveLibp2pPeerId(): PeerId = PeerId.fromPubKey(deriveLibp2pPrivKey().publicKey())
