type Blob = Vec<u8>;
struct Sneaky { body: Blob }
impl FixedStorage for Sneaky {}
struct Gen<T>(T);
impl FixedStorage for Gen<Vec<u8>> {}
