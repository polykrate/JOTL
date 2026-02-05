3. Notational Conventions
Much as in the Ethereum Yellow Paper, a number of
notational conventions are used throughout the present
work. We define them here for clarity. The Ethereum
Yellow Paper itself may be referred to henceforth as the
YP.
3.1. Typography. We use a number of different type-
faces to denote different kinds of terms. Where a term is
used to refer to a value only relevant within some localized
section of the document, we use a lower-case roman letter
e.g. x, y (typically used for an item of a set or sequence)
or e.g. i, j (typically used for numerical indices). Where
we refer to a Boolean term or a function in a local context,
we tend to use a capitalized roman alphabet letter such as
A, F . If particular emphasis is needed on the fact a term
is sophisticated or multidimensional, then we may use a
bold typeface, especially in the case of sequences and sets.
For items which retain their definition throughout the
present work, we use other typographic conventions. Sets
are usually referred to with a blackboard typeface, e.g. N
refers to all natural numbers including zero. Sets which
may be parameterized may be subscripted or be followed
by parenthesized arguments. Imported functions, used by
the present work but not specifically introduced by it, are
written in calligraphic typeface, e.g. H the Blake2 cryp-
tographic hashing function. For other non-context depen-
dent functions introduced in the present work, we use up-
per case Greek letters, e.g. Υ denotes the state transition
function.
Values which are not fixed but nonetheless hold some
consistent meaning throughout the present work are de-
noted with lower case Greek letters such as σ, the state
6Earlier node versions utilized Arweave network, a decentralized data store, but this was found to be unreliable for the data throughput
which Solana required.
JAM: JOIN-ACCUMULATE MACHINE DRAFT 0.7.2 - September 15, 2025 6
identifier. These may be placed in bold typeface to denote
that they refer to an abnormally complex value.
3.2. Functions and Operators. We define the precedes
relation to indicate that one term is defined in terms of
another. E.g. y ≺ x indicates that y may be defined purely
in terms of x:
y ≺ x ⇐⇒ ∃f ∶ y = f (x)(3.1)
The substitute-if-nothing function U is equivalent to
the first argument which is not ∅, or ∅ if no such argu-
ment exists:
U(a0, . . . an) ≡ ax ∶ (ax ≠ ∅ ∨ x = n), x−1
⋀
i=0
ai = ∅(3.2)
Thus, e.g. U(∅, 1, ∅, 2) = 1 and U(∅, ∅) = ∅.
3.3. Sets. Given some set s, its power set and cardinal-
ity are denoted as {[ s ]} and SsS. When forming a power
set, we may use a numeric subscript in order to restrict
the resultant expansion to a particular cardinality. E.g.
{[ { 1, 2, 3 } ]}2 = { { 1, 2 }, { 1, 3 }, { 2, 3 } }.
Sets may be operated on with scalars, in which case
the result is a set with the operation applied to each el-
ement, e.g. { 1, 2, 3 } + 3 = { 4, 5, 6 }. Functions may also
be applied to all members of a set to yield a new set,
but for clarity we denote this with a # superscript, e.g.
f #({ 1, 2 }) ≡ { f (1), f (2) }.
We denote set-disjointness with the relation ⫰. For-
mally:
A ∩ B = ∅ ⇐⇒ A ⫰ B
We commonly use ∅ to indicate that some term is
validly left without a specific value. Its cardinality is
defined as zero. We define the operation ? such that
A? ≡ A ∪ { ∅ } indicating the same set but with the addi-
tion of the ∅ element.
The term ∇ is utilized to indicate the unexpected fail-
ure of an operation or that a value is invalid or unexpected.
(We try to avoid the use of the more conventional  here
to avoid confusion with Boolean false, which may be in-
terpreted as some successful result in some contexts.)
3.4. Numbers. N denotes the set of naturals including
zero whereas Nn implies a restriction on that set to val-
ues less than n. Formally, N = { 0, 1, . . . } and Nn =
{ x S x ∈ N, x < n }.
Z denotes the set of integers. We denote Za...b to be
the set of integers within the interval [a, b). Formally,
Za...b = { x S x ∈ Z, a ≤ x < b }. E.g. Z2...5 = { 2, 3, 4 }. We
denote the offset/length form of this set as Za⋅⋅⋅+b, a short
form of Za...a+b.
It can sometimes be useful to represent lengths of se-
quences and yet limit their size, especially when dealing
with sequences of octets which must be stored practically.
Typically, these lengths can be defined as the set N232 .
To improve clarity, we denote NL as the set of lengths of
octet sequences and is equivalent to N232 .
We denote the % operator as the modulo operator,
e.g. 5 % 3 = 2. Furthermore, we may occasionally express
a division result as a quotient and remainder with the
separator R , e.g. 5 ÷ 3 = 1 R 2.
3.5. Dictionaries. A dictionary is a possibly partial
mapping from some domain into some co-domain in much
the same manner as a regular function. Unlike functions
however, with dictionaries the total set of pairings are
necessarily enumerable, and we represent them in some
data structure as the set of all (key ↦ value) pairs. (In
such data-defined mappings, it is common to name the
values within the domain a key and the values within the
co-domain a value, hence the naming.)
Thus, we define the formalism jK → Vo to denote a dic-
tionary which maps from the domain K to the range V.
It is a subset of the power set of pairs ⎧
⎩K, V ⎫
⎭:
(3.3) jK → Vo ⊂ {[⎧
⎩K, V⎫
⎭]}
The subset is caused by a constraint that a dictionary’s
members must associate at most one unique value for any
given key k:
(3.4) ∀K, V, d ∈ jK → Vo ∶ ∀(k, v) ∈ d ∶ ∃!v′ ∶ k, v′ ∈ d
In the context of a dictionary we denote the pairs with
a mapping notation:
jK → Vo ≡ {[⎧
⎩K → V⎫
⎭]}(3.5)
p ∈⎧
⎩K → V⎫
⎭⇔ ∃k ∈ K, v ∈ V, p ≡ (k ↦ v)(3.6)
This assertion allows us to unambiguously define the
subscript and subtraction operator for a dictionary d:
∀K, V, d ∈ jK → Vo ∶ d[k] ≡
⎧⎪⎪
⎨
⎪⎪⎩
v if ∃k ∶ (k ↦ v) ∈ d
∅ otherwise
(3.7)
∀K, V, d ∈ jK → Vo, s ⊆ K ∶
d ∖ s ≡ { (k ↦ v) ∶ (k ↦ v) ∈ d, k ~∈ s }
(3.8)
Note that when using a subscript, it is an implicit as-
sertion that the key exists in the dictionary. Should the
key not exist, the result is undefined and any block which
relies on it must be considered invalid.
To denote the active domain (i.e. set of keys) of a dic-
tionary d ∈ jK → V o, we use K(d) ⊆ K and for the range
(i.e. set of values), V(d) ⊆ V . Formally:
∀K, V, d ∈ jK → Vo ∶ K(d) ≡ { k S ∃v ∶ (k ↦ v) ∈ d }(3.9)
∀K, V, d ∈ jK → Vo ∶ V(d) ≡ { v S ∃k ∶ (k ↦ v) ∈ d }(3.10)
Note that since the co-domain of V() is a set, should
different keys with equal values appear in the dictionary,
the set will only contain one such value.
Dictionaries may be combined through the union oper-
ator ∪, which priorities the right-side operand in the case
of a key-collision:
(3.11) ∀d ∈ K, V, (d, e) ∈ jK → Vo2 ∶ d∪e ≡ (d∖K(e))∪e
3.6. Tuples. Tuples are groups of values where each item
may belong to a different set. They are denoted with
parentheses, e.g. the tuple t of the naturals 3 and 5 is de-
noted t = (3, 5), and it exists in the set of natural pairs
sometimes denoted N ×N, but denoted in the present work
as ⎧
⎩N, N⎫
⎭.
We have frequent need to refer to a specific item within
a tuple value and as such find it convenient to declare a
name for each item. E.g. we may denote a tuple with two
named natural components a and b as T = ⎧
⎩a ∈ N, b ∈ N⎫
⎭.
We would denote an item t ∈ T through subscripting its
name, thus for some t = (a▸
▸ 3, b ▸
▸ 5), ta = 3 and tb = 5.
JAM: JOIN-ACCUMULATE MACHINE DRAFT 0.7.2 - September 15, 2025 7
3.7. Sequences. A sequence is a series of elements with
particular ordering not dependent on their values. The set
of sequences of elements all of which are drawn from some
set T is denoted ⟦T ⟧, and it defines a partial mapping
N → T . The set of sequences containing exactly n ele-
ments each a member of the set T may be denoted ⟦T ⟧n
and accordingly defines a complete mapping Nn → T . Sim-
ilarly, sets of sequences of at most n elements and at least
n elements may be denoted ⟦T ⟧∶n and ⟦T ⟧n∶ respectively.
Sequences are subscriptable, thus a specific item at in-
dex i within a sequence s may be denoted s[i], or where
unambiguous, si. A range may be denoted using an ellip-
sis for example: [0, 1, 2, 3]...2 = [0, 1] and [0, 1, 2, 3]1⋅⋅⋅+2 =
[1, 2]. The length of such a sequence may be denoted SsS.
We denote modulo subscription as s[i]↺ ≡ s[ i % SsS ].
We denote the final element x of a sequence s = [..., x]
through the function last(s) ≡ x.
3.7.1. Construction. We may wish to define a sequence
in terms of incremental subscripts of other values:
[x0, x1, . . . ]...n denotes a sequence of n values beginning
x0 continuing up to xn−1. Furthermore, we may also
wish to define a sequence as elements each of which
are a function of their index i; in this case we denote
[f (i) S i <− Nn] ≡ [f (0), f (1), . . . , f (n − 1)]. Thus, when
the ordering of elements matters we use <− rather than
the unordered notation ∈. The latter may also be written
in short form [f (i <− Nn)]. This applies to any set which
has an unambiguous ordering, particularly sequences, thus
i2 T i <− [1, 2, 3] = [1, 4, 9]. Multiple sequences may be
combined, thus [i ⋅ j S i <− [1, 2, 3], j <− [2, 3, 4]] = [2, 6, 12].
As with sets, we use explicit notation f # to denote a
function mapping over all items of a sequence.
Sequences may be constructed from sets or other se-
quences whose order should be ignored through sequence
ordering notation [i ∈ X ^
^ f (i)], which is defined to result
in the set or sequence of its argument except that all ele-
ments i are placed in ascending order of the corresponding
value f (i).
The key component may be elided in which case it
is assumed to be ordered by the elements directly; i.e.
[i ∈ X] ≡ [i ∈ X ^
^ i]. [i ∈ X _
_ i] does the same, but excludes
any duplicate values of i. E.g. assuming s = [1, 3, 2, 3],
then [i ∈ s _
_ i] = [1, 2, 3] and [i ∈ s ^
^ −i] = [3, 3, 2, 1].
Sets may be constructed from sequences with the reg-
ular set construction syntax, e.g. assuming s = [1, 2, 3, 1],
then { a S a ∈ s } would be equivalent to { 1, 2, 3 }.
Sequences of values which themselves have a defined
ordering have an implied ordering akin to a regular dic-
tionary, thus [1, 2, 3] < [1, 2, 4] and [1, 2, 3] < [1, 2, 3, 1].
3.7.2. Editing. We define the sequence concatenation op-
erator ⌢ such that [x0, x1, . . . , y0, y1, . . . ] ≡ x ⌢ y. For
sequences of sequences, we define a unary concatenate-all
operator: Ìx ≡ x0 ⌢ x1 ⌢ . . . . Further, we denote ele-
ment concatenation as x i ≡ x ⌢ [i]. We denote the
sequence made up of the first n elements of sequence s to
be Ð→s n ≡ [s0, s1, . . . , sn−1], and only the final elements as
←Ðs n.
We define Tx as the transposition of the sequence-of-
sequences x, fully defined in equation H.3. We may also
apply this to sequences-of-tuples to yield a tuple of se-
quences.
We denote sequence subtraction with a slight modifica-
tion of the set subtraction operator; specifically, some se-
quence s excepting the left-most element equal to v would
be denoted s m { v }.
3.7.3. Boolean values. bs denotes the set of Boolean
strings of length s, thus bs = ⟦{ , ⊺ }⟧s. When dealing
with Boolean values we may assume an implicit equiva-
lence mapping to a bit whereby ⊺ = 1 and  = 0, thus
b◻ = ⟦N2⟧◻. We use the function bits(B) ∈ b to de-
note the sequence of bits, ordered with the most signif-
icant first, which represent the octet sequence B, thus
bits([160, 0]) = [1, 0, 1, 0, 0, . . . ].
The unary-not operator applies to both boolean val-
ues and sequences of boolean values, thus ¬⊺ =  and
¬[⊺, ] = [, ⊺].
3.7.4. Octets and Blobs. B denotes the set of octet strings
(“blobs”) of arbitrary length. As might be expected, Bx
denotes the set of such sequences of length x. B$ denotes
the subset of B which are ascii-encoded strings. Note that
while an octet has an implicit and obvious bijective rela-
tionship with natural numbers less than 256, and we may
implicitly coerce between octet form and natural number
form, we do not treat them as exactly equivalent entities.
In particular for the purpose of serialization, an octet is
always serialized to itself, whereas a natural number may
be serialized as a sequence of potentially several octets,
depending on its magnitude and the encoding variant.
3.7.5. Shuffling. We define the sequence-shuffle function
F, originally introduced by Fisher and Yates 1938, with an
efficient in-place algorithm described by Wikipedia 2024.
This accepts a sequence and some entropy and returns a
sequence of the same length with the same elements but
in an order determined by the entropy. The entropy may
be provided as either an indefinite sequence of naturals or
a hash. For a full definition see appendix F.
3.8. Cryptography.
3.8.1. Hashing. H denotes the set of 256-bit values equiv-
alent to B32. All hash functions in the present work out-
put to this type and H0 is the value equal to [0]32. We
assume a function H(m ∈ B) ∈ H denoting the Blake2b
256-bit hash introduced by Saarinen and Aumasson 2015
and a function HK (m ∈ B) ∈ H denoting the Keccak 256-
bit hash as proposed by Bertoni et al. 2013 and utilized
by Wood 2014.
The inputs of a hash function should be expected to
be passed through our serialization codec E to yield an
octet sequence to which the cryptography may be ap-
plied. (Note that an octet sequence conveniently yields
an identity transform.) We may wish to interpret a se-
quence of octets as some other kind of value with the as-
sumed decoder function E−1(x ∈ B). In both cases, we may
subscript the transformation function with the number of
octets we expect the octet sequence term to have. Thus,
r = E4(x ∈ N) would assert x ∈ N232 and r ∈ B4, whereas
s = E−1
8 (y) would assert y ∈ B8 and s ∈ N264 .
3.8.2. Signing Schemes. ¯Vk ⟨m⟩ ⊂ B64 is the set of valid
Ed25519 signatures, defined by Josefsson and Liusvaara
2017, made through knowledge of a secret key whose pub-
lic key counterpart is k ∈ H and whose message is m. To
aid readability, we denote the set of valid public keys ¯H.
JAM: JOIN-ACCUMULATE MACHINE DRAFT 0.7.2 - September 15, 2025 8
We denote the set of valid Bandersnatch public keys as
∽
H, defined in appendix G. ∽
Vm∈B
k∈ ∽
H ⟨x ∈ B⟩ ⊂ B96 is the set of
valid singly-contextualized signatures of utilizing the se-
cret counterpart to the public key k, some context x and
message m.
○
Vm∈B
r∈ ○
B
⟨x ∈ B⟩ ⊂ B784, meanwhile, is the set of valid Ban-
dersnatch Ringvrf deterministic singly-contextualized
proofs of knowledge of a secret within some set of secrets
identified by some root in the set of valid roots ○
B ⊂ B144.
We denote Os ∈ D ∽
HI ∈ ○
B to be the root specific to the set
of public key counterparts s. A root implies a specific set
of Bandersnatch key pairs, knowledge of one of the secrets
would imply being capable of making a unique, valid—and
anonymous—proof of knowledge of a unique secret within
the set.
Both the Bandersnatch signature and Ringvrf proof
strictly imply that a member utilized their secret key in
combination with both the context x and the message m;
the difference is that the member is identified in the for-
mer and is anonymous in the latter. Furthermore, both
define a vrf output, a high entropy hash influenced by
x but not by m, formally denoted Y ○
Vm
r ⟨x⟩ ⊂ H and
Y ∽
Vm
k ⟨x⟩ ⊂ H.
We use BLS
B ⊂ B144 to denote the set of public keys for
the bls signature scheme, described by Boneh, Lynn, and
Shacham 2004, on curve bls12-381 defined by Hopwood
et al. 2020. We correspondingly use the notationBLS
Vk ⟨m⟩ to
denote the set of valid bls signatures for public key k ∈BLS
B
and message m ∈ B.
We define the signature functions for creating valid sig-
natures; ¯S(m) ∈ ¯Vk ⟨m⟩, BLS
S(m) ∈ BLS
Vk ⟨m⟩. We assert that
the ability to compute a result for this function relies on
knowledge of a secret key.