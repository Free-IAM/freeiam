from _typeshed import Incomplete

__all__ = ['encode']

class AbstractItemEncoder:
    supportIndefLenMode: bool
    eooIntegerSubstrate: Incomplete
    eooOctetsSubstrate: Incomplete
    def encodeTag(self, singleTag, isConstructed): ...
    def encodeLength(self, length, defMode): ...
    def encodeValue(self, value, asn1Spec, encodeFun, **options) -> None: ...
    def encode(self, value, asn1Spec=None, encodeFun=None, **options): ...

class EndOfOctetsEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class BooleanEncoder(AbstractItemEncoder):
    supportIndefLenMode: bool
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class IntegerEncoder(AbstractItemEncoder):
    supportIndefLenMode: bool
    supportCompactZero: bool
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class BitStringEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class OctetStringEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class NullEncoder(AbstractItemEncoder):
    supportIndefLenMode: bool
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class ObjectIdentifierEncoder(AbstractItemEncoder):
    supportIndefLenMode: bool
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class RealEncoder(AbstractItemEncoder):
    supportIndefLenMode: bool
    binEncBase: int
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class SequenceEncoder(AbstractItemEncoder):
    omitEmptyOptionals: bool
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class SequenceOfEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class ChoiceEncoder(AbstractItemEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class AnyEncoder(OctetStringEncoder):
    def encodeValue(self, value, asn1Spec, encodeFun, **options): ...

class Encoder:
    fixedDefLengthMode: Incomplete
    fixedChunkSize: Incomplete
    def __init__(self, tagMap, typeMap={}) -> None: ...
    def __call__(self, value, asn1Spec=None, **options): ...

def encode(Any) -> bytes: ...
