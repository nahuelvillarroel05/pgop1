"""The literal engine's input binding, extracted from acquisition_memory_v1."""

from dataclasses import dataclass

from .acquisition_text_v1 import Authority


@dataclass(frozen=True)
class TextInput:
    catalog_raw: bytes
    policy_raw: bytes
    grant_raw: bytes
    authority: Authority
