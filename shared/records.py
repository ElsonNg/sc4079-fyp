"""Flat saved records for models that group their metadata internally."""

from collections.abc import Mapping
from typing import Any, ClassVar

from pydantic import BaseModel, model_serializer, model_validator


class MetadataRecord(BaseModel):
    """Accept grouped or legacy input and retain the existing flat output format."""

    record_exclusions: ClassVar[dict[str, set[str]]] = {}

    @model_validator(mode="before")
    @classmethod
    def read_metadata(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        record = dict(value)
        for group in ("advisory", "origin"):
            if group not in record:
                names = cls.model_fields[group].annotation.model_fields
                record[group] = {name: record.pop(name) for name in names if name in record}
        return record

    @model_serializer(mode="wrap")
    def write_metadata(self, handler):
        record = handler(self)
        for group in ("advisory", "origin"):
            metadata = record.pop(group, {})
            excluded = self.record_exclusions.get(group, set())
            record.update({name: value for name, value in metadata.items() if name not in excluded})
        return record
