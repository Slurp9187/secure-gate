/* outer /* inner
   struct D { v: Vec<u8> }
   impl FixedStorage for D {}
   */ still in outer
   impl FixedStorage for D {}
*/
struct Real { v: Vec<u8> }
impl FixedStorage for Real {}
