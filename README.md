# `packets-are-structs`
Packets are complex to serialize and deserialize, with variadic sections, and specific packing rules.  
This crate challenges Rust's type system to provide generic, useable and safe structs representing a variety of packets as they would appear on-the-wire.  
