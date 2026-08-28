# Canonical Packed Clarity Value Format, Version 1

## Status and scope

This document specifies the byte-level format emitted and accepted by the `clarity-types`
packed-value codec. It is normative for Version 1 of that codec.

This format is a local storage representation. It is not Clarity consensus serialization and does
not change value hashes, state roots, protocol costs, or values visible to contracts. A stored
record retains the byte length of its equivalent consensus serialization so existing cost accounting
remains unchanged.

The format consists of two independent byte streams:

- a packed value record, decoded with a caller-supplied `TypeSignature`; and
- an optional active-shape descriptor, used to reconstruct exact consensus bytes without a
  `TypeSignature`.

Ordinary typed reads require only the packed value record. Generic reads, integrity audits, and
compatibility reads for historical unsanitized values whose cached schema omits active data require
both streams.

The packed value record has no in-record version byte. Its containing storage format MUST select
this grammar out of band. The active-shape descriptor has its own Version 1 byte because it can be
parsed independently.

## Terminology and notation

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe format requirements.

The following notation is used:

| Notation | Meaning |
| ---- | ---- |
| `u8` | One unsigned byte |
| `u16le` | Two-byte unsigned little-endian integer |
| `u32le` | Four-byte unsigned little-endian integer |
| `u32be` | Four-byte unsigned big-endian integer |
| `bytes[n]` | Exactly `n` uninterpreted bytes |
| `bytes[*]` | All bytes remaining in the enclosing frame |
| `body(T)` | Packed body interpreted under type or active shape `T` |
| `varuint` | Minimal unsigned LEB128 integer |

An enclosing frame is the complete record body, a directory-delimited child, a fixed-width child, or
a scalar-lane element. Lengthless encodings consume the remainder of their enclosing frame.

Unless stated otherwise:

- storage lengths, list counts, and directory offsets are little-endian;
- integer value bytes are big-endian; and
- lengths reconstructed for Clarity consensus serialization are big-endian, as required by that
  existing format.

All length and offset arithmetic MUST be checked for overflow.

## Canonicality invariant

For a supported active Clarity `Value`, the packed bytes MUST be a pure function of the value. They
MUST NOT depend on:

- the execution epoch;
- declared sequence bounds;
- inactive optional or response types;
- callable subtype metadata; or
- any other part of the declared `TypeSignature` not present in the active value.

Schema and epoch are admission and decoding inputs, not physical-layout inputs. Two values with
identical canonical consensus bytes MUST produce identical packed records and identical active-shape
descriptors.

Encoders MUST emit the one canonical representation described below. Packed-record decoders MUST
reject non-minimal scalar and directory widths, trailing bytes, invalid padding, and disagreement
with the declared logical consensus length. Descriptor parsing enforces its local grammar and
minimality rules; the full audit defined below additionally proves that a structurally valid
descriptor is canonical for its packed value.

## Packed value record

Every record is:

```text
packed_record := consensus_byte_len:u32le value_body:bytes[*]
```

`consensus_byte_len` is the exact length, in bytes, of the equivalent canonical Clarity consensus
serialization. It includes the consensus type prefix and any consensus length, field-name, or
container-count bytes omitted from the packed body.

The packed header is therefore exactly four bytes. The header is not a payload length and not a
format version.

A typed decoder MUST compute the logical consensus length while decoding and MUST reject the record
unless it equals `consensus_byte_len`. A schema-free reconstructor MUST produce exactly
`consensus_byte_len` bytes and MUST reject an append that would exceed it.

## Scalar and sequence bodies

### Signed integer

```text
body(int) := twos_complement_be:bytes[1..16]
```

The body is the shortest non-empty two's-complement big-endian representation of the `i128`.
Redundant leading `00` or `ff` sign-extension bytes are forbidden. Zero is encoded as one `00` byte.

Consensus reconstruction prepends the Clarity integer prefix and sign-extends the body to 16 bytes.

### Unsigned integer

```text
body(uint) := magnitude_be:bytes[1..16]
```

The body is the shortest non-empty unsigned big-endian representation of the `u128`. A multi-byte
value MUST NOT begin with `00`. Zero is encoded as one `00` byte.

Consensus reconstruction prepends the Clarity unsigned-integer prefix and zero-extends the body to
16 bytes.

### Boolean

```text
body(bool) := 00 | 01
```

`00` is false and `01` is true. No other value is valid.

### Buffer

```text
body(buffer) := payload:bytes[*]
```

The enclosing frame supplies the physical length. Typed decoding MUST reject a payload exceeding the
declared buffer bound.

Consensus reconstruction prepends the buffer prefix and payload length as
`u32be`.

### ASCII string

```text
body(ascii) := characters:bytes[*]
```

Every byte MUST satisfy Clarity's ASCII grammar: ASCII alphanumeric, punctuation, or whitespace. The
enclosing frame supplies the byte length. Typed decoding MUST also enforce the declared character
bound.

Consensus reconstruction prepends the ASCII-string prefix and byte length as `u32be`.

### UTF-8 string

```text
body(utf8) := utf8_bytes:bytes[*]
```

The body MUST be valid UTF-8. Typed decoding MUST enforce the declared bound in Unicode scalar
values, not bytes.

Consensus reconstruction prepends the UTF-8-string prefix and byte length as `u32be`.

## Principals and callables

Principals use a one-byte physical kind:

```text
body(standard_principal) := 00 version:u8 hash160:bytes[20]

body(contract_principal) :=
    01 issuer_version:u8 issuer_hash160:bytes[20]
    contract_name:bytes[*]
```

The principal version MUST be less than 32. A contract name MUST be non-empty, valid UTF-8, no
longer than Clarity's 128-byte name bound, and accepted by the Clarity contract-name grammar.

The contract-name length is omitted because the enclosing frame supplies it. A standard-principal
body is 22 bytes. A contract-principal body is `22 + contract_name.len()` bytes.

A callable contract MUST use the contract-principal body above. Trait identity is not stored because
it is absent from the callable's consensus bytes. Typed decoding restores callable identity from the
declared schema:

- `CallableType::Trait(expected_trait)` restores `expected_trait`;
- `PrincipalType` decodes the same bytes as an ordinary contract principal.

Typed encoding MUST use Clarity's recursive `TypeSignature::admits` rules. Before Epoch 2.1,
`CallableType` MUST be rejected as unsupported. A plain callable under `PrincipalType` MUST be
rejected before Epoch 2.1 and admitted from Epoch 2.1 onward. A trait-qualified callable MUST NOT be
admitted under `PrincipalType`.

`CallableType::Principal` and the historical `TraitReferenceType` are not persisted storage schemas
and MUST be rejected. On typed decode, the pre-2.1 rejection applies to `CallableType::Trait`.
`PrincipalType` decodes the physical body as an ordinary `Value::Principal`, so it has no callable
epoch gate.

Schema-free reconstruction always emits the canonical contract-principal consensus bytes. Those
bytes intentionally contain no trait identity.

## Optional and response bodies

### Optional

```text
body(optional_none) := 00
body(optional_some(T)) := 01 body(T)
```

`none` MUST contain no bytes after its tag. `some` consumes the remainder of its frame as its active
child.

### Response

```text
body(response_err(E)) := 00 body(E)
body(response_ok(T))  := 01 body(T)
```

The inactive response branch contributes no physical bytes and MUST NOT affect parent framing.

## Fixed-width classification

Only the following active values are fixed-width:

- a Boolean, with width 1; and
- a tuple whose every active field is recursively fixed-width, with width equal to the checked sum
  of its field widths.

All other active values are variable-width. In particular, integers, principals, callables,
sequences, optionals, and responses remain variable-width even when one particular value happens to
have a fixed physical length. This rule prevents declared bounds and inactive branches from changing
parent layout.

## Offset directories

Variable-width tuple fields and list elements use a canonical offset directory:

```text
directory(N) :=
    width_code:u8
    offsets:offset[N + 1]
    child_data:bytes[*]
```

The width code and encoded offset type are:

| `width_code` | Offset encoding | Allowed child-data length |
| ---- | ---- | ---- |
| `00` | `u8` | `0..=255` |
| `01` | `u16le` | `256..=65,535` |
| `02` | `u32le` | `65,536..=u32::MAX` |

The width MUST be the narrowest width capable of representing the complete `child_data` length.

Offsets are relative to the start of `child_data`. The following conditions MUST hold:

- `offsets[0] == 0`;
- `offsets[N] == child_data.len()`;
- offsets are monotonically non-decreasing; and
- every offset is within `child_data`.

Child `i` occupies `child_data[offsets[i]..offsets[i + 1]]`. Repeated offsets are valid when a child
has an empty body.

The child count is supplied by the tuple schema, active-shape descriptor, or the list's encoded
count; it is not repeated in the directory.

## Tuple body

Tuple field names and field count are omitted from the packed body. Fields are encoded in the
canonical order of the value's `ClarityName` map.

If every active field is fixed-width:

```text
body(tuple) := body(field_0) ... body(field_N-1)
```

Otherwise:

```text
body(tuple) := directory(N)
```

Typed decoding obtains names, child types, and count from the expected tuple schema. Schema-free
reconstruction obtains them from the active-shape descriptor. Field names MUST be strictly
increasing and the complete tuple body MUST be consumed.

## List body

Every list begins with its active element count:

```text
body(list) := count:u32le element_region:bytes[*]
```

An empty list has `count == 0` and an empty `element_region`.

For a non-empty list, the encoder selects exactly one layout from the active elements, in the
following order:

1. unsigned-integer lane, if every element is a `uint`;
2. signed-integer lane, if every element is an `int`;
3. Boolean lane, if every element is a Boolean;
4. fixed concatenation, if every element is fixed-width; or
5. offset-directory framing otherwise.

The declared list element type and maximum bound MUST NOT select the physical layout.

### Integer lanes

```text
uint_lane := uint_element:bytes[W] ...
int_lane  := int_element:bytes[W] ...
```

`W` is inferred as `element_region.len() / count`; it is not stored separately. The region MUST be
non-empty and evenly divisible by the non-zero count. `W` MUST be in `1..=16`.

For an unsigned lane, `W` is the maximum minimal unsigned width of all active elements, with a
minimum lane width of one. Each element is zero-extended to `W` bytes. If `W > 1`, at least one
element's first byte MUST be non-zero.

For a signed lane, `W` is the maximum minimal two's-complement width of all active elements, with a
minimum lane width of one. Each element is sign-extended to `W` bytes. If `W > 1`, at least one
element MUST require exactly `W` bytes.

### Boolean lane

```text
bool_lane := bits:bytes[ceil(count / 8)]
```

Element `i` is bit `i % 8` of byte `i / 8`; the least-significant bit is used first. Unused high
bits in the final byte MUST be zero.

### Fixed-width elements

Fixed-width element bodies are concatenated with no directory. For historical heterogeneous lists,
each active element's own fixed width is used during schema-free reconstruction. Ordinary typed
lists use the one width implied by their element schema.

### Variable-width elements

The element region is `directory(count)`. Each directory child is one complete packed element body.

## Active-shape descriptor

The active-shape descriptor supplies only information omitted from packed bytes that is necessary
for schema-free reconstruction.

```text
value_shape := version:u8 shape
version     := 01
```

The descriptor MUST contain exactly one shape with no trailing bytes. Its total length MUST NOT
exceed `BOUND_VALUE_SHAPE_BYTES` (currently 2,097,153 bytes), and its recursive depth MUST NOT
exceed `MAX_TYPE_DEPTH` (currently 32 nodes including the root).

### Shape opcodes

| Opcode | Shape | Following bytes |
| ---- | ---- | ---- |
| `00` | Signed integer | None |
| `01` | Unsigned integer | None |
| `02` | Boolean | None |
| `03` | Buffer | None |
| `04` | ASCII string | None |
| `05` | UTF-8 string | None |
| `06` | Principal or callable identity | None |
| `07` | Optional `none` | None |
| `08` | Optional `some` | One child shape |
| `09` | Response `ok` only | One `ok` child shape |
| `0a` | Response `err` only | One `err` child shape |
| `0b` | Response with observed `ok` and `err` shapes | `ok` shape, then `err` shape |
| `0c` | Tuple | Tuple descriptor |
| `0d` | Empty list | None |
| `0e` | Non-empty list with one shared shape | One element shape |
| `0f` | Historical list with per-element shapes | List-elements descriptor |

Unknown opcodes MUST be rejected.

`06` deliberately merges ordinary principals and callable contracts because their canonical
consensus bytes contain the same contract-principal identity.

`0b` normally arises by merging response shapes across list elements. A shape for one standalone
response contains only its active branch.

### Tuple descriptor

```text
tuple_shape :=
    0c field_count:varuint
    (name_len:u8 name:bytes[name_len] child_shape) * field_count
```

`field_count` MUST be non-zero. Each name MUST be a valid `ClarityName`, and names MUST be strictly
increasing. The descriptor records active child shapes in the same order used by the packed tuple
body.

### List descriptors

```text
empty_list_shape := 0d
shared_list_shape := 0e element_shape
per_element_list_shape := 0f element_count:varuint element_shape * element_count
```

`element_count` in a per-element descriptor MUST be non-zero and MUST equal the packed list count
during reconstruction.

Ordinary lists MUST use one shared element shape whenever all element shapes can merge. The
per-element form is reserved for historical unsanitized lists whose active shapes cannot merge. A
parser MUST reject a per-element descriptor whose shapes are mergeable.

Shape merging follows these rules:

- identical scalar, sequence, or principal shapes merge to themselves;
- absent and present optional child shapes merge to the present shape;
- response shapes merge their observed `ok` and `err` branches independently;
- tuples merge only when names and arity match, then merge each child;
- list shapes recursively merge their element shapes; and
- incompatible shapes do not merge.

### Descriptor varuint

Tuple field counts and per-element list counts use minimal unsigned LEB128:

- the low seven bits of each byte contribute one group, least-significant group first;
- bit 7 indicates another byte follows;
- the terminal byte MUST NOT contain a zero group when more than one byte was used; and
- overflow of the host `usize` MUST be rejected.

## Typed decoding

A typed decoder receives a complete packed record, expected `TypeSignature`, and execution epoch. It
MUST:

1. parse the four-byte logical-length header;
2. decode the complete body under the expected schema;
3. enforce sequence and list bounds, tuple fields, callable rules, and epoch rules;
4. enforce every canonical scalar, lane, and framing rule;
5. reject unsupported active `NoType` and analysis-only `ListUnionType` states;
6. reject missing or trailing bytes; and
7. compare its accumulated consensus length with the record header.

The expected schema provides omitted tuple names, declared bounds, inactive wrapper branches, list
element types, and callable trait identity. It MUST NOT change the physical interpretation selected
by the canonical active value.

## Schema-free reconstruction and audit

Schema-free reconstruction receives a complete packed record and active-shape descriptor. It MUST
validate both grammars and reconstruct exactly the canonical Clarity consensus bytes described by
the pair.

Structural reconstruction alone proves that the pair is well framed and produces the declared
logical length. It does not prove that the descriptor is the most specific canonical descriptor for
those bytes.

A full canonical audit MUST additionally:

1. deserialize the reconstructed consensus bytes as one exact untyped Clarity value;
2. reserialize it and require byte-for-byte equality;
3. re-encode its packed record and active-shape descriptor; and
4. require both outputs to equal the stored inputs byte for byte.

This catches structurally valid but over-general descriptors, non-canonical consensus encodings, and
any divergence between typed encoding and migration transcoding.

## Bounds

Version 1 enforces the following current Clarity limits:

| Item | Limit |
| ---- | ---- |
| Canonical consensus value | `BOUND_VALUE_SERIALIZATION_BYTES` = 2,097,152 bytes |
| Active-shape descriptor | `BOUND_VALUE_SHAPE_BYTES` = 2,097,153 bytes |
| Active-shape depth | `MAX_TYPE_DEPTH` = 32 |
| Integer body or lane width | 16 bytes |
| Packed directory offset | `u32::MAX` |

The packed body has a conservative expansion bound:

```text
BOUND_PACKED_VALUE_BODY_BYTES =
    BOUND_VALUE_SERIALIZATION_BYTES
    + MAX_VALUE_SIZE * (4 + 5)
    + 5
```

With the current constants, this is 11,534,341 bytes. The four-byte packed record header is not
included in that bound.

The active-shape bound is one byte larger than the maximum consensus serialization. For a canonical
descriptor derived from a legal value, every shape node and tuple name is covered by at least as
many bytes in the corresponding consensus value. Merged optional, response, and list shapes
describe multiple active values whose combined consensus bytes cover every merged child. The
descriptor's version byte is its only byte without a consensus counterpart. Parsers apply the same
bound as a conservative resource ceiling before a full canonicality audit.

## Golden examples

All examples show complete packed records, including the four-byte logical length header.

### Unsigned integer 256

The canonical consensus representation is 17 bytes. The packed magnitude is the minimal big-endian
`01 00`:

```text
11 00 00 00  01 00
^^^^^^^^^^^  ^^^^^
length = 17  uint body
```

### List `(list u0 u255 u256)`

The logical consensus length is `5 + 3 * 17 = 56` bytes. All elements share a two-byte unsigned
lane:

```text
38 00 00 00  03 00 00 00  00 00  00 ff  01 00
^^^^^^^^^^^  ^^^^^^^^^^^  ^^^^^  ^^^^^  ^^^^^
length = 56  count = 3     u0     u255   u256
```

### Tuple `{ a: u1, b: true }`

The tuple is variable-width because integers are not fixed-width. Its two children occupy a
one-byte-offset directory:

```text
1b 00 00 00  00  00 01 02  01 01
^^^^^^^^^^^  ^^  ^^^^^^^^  ^^^^^
length = 27  W=1 offsets   child data
```

Its active-shape descriptor is:

```text
01  0c 02  01 61 01  01 62 02
^^  ^^^^^  ^^^^^^^^  ^^^^^^^^
V1  tuple   a: uint   b: bool
```

## Versioning rule

Any change that alters bytes emitted for an already-supported value requires a new containing
storage-format version. Any incompatible change to the active-shape grammar also requires a new
descriptor version.

Readers MUST fail closed on unsupported versions. Writers MUST NOT emit two different physical
representations for the same canonical value within one content-addressed store.
