from pydantic import BaseModel


class FunctionUnit(BaseModel):
    name: str | None = None
    node_type: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    source: str
    language: str = "javascript"
