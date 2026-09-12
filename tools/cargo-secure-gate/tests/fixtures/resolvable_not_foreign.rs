// A peer sweep reported both of these as reporting NOTHING at any severity in a
// regex implementation -- the resolver found the definition, failed on the field
// type, and returned "no problem". Silence on an unresolvable marker is the one
// output an auditor must never produce. Both must be errors here, because both
// are resolvable: the alias is one lookup away, and the impl site supplies the
// very argument its struct is generic over.
use secure_gate::FixedStorage;

type Blob = Vec<u8>;
struct Sneaky {
    body: Blob,
}
impl FixedStorage for Sneaky {}

struct Gen<T>(T);
impl FixedStorage for Gen<Vec<u8>> {}

// The same struct instantiated at a fixed payload is sound, and must stay clean.
struct Pair<T>(T, [u8; 4]);
impl FixedStorage for Pair<u64> {}
