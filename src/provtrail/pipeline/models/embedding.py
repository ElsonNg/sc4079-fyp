from pydantic import BaseModel


class ModelSpec(BaseModel):
    model_id: str
    hf_name: str
    label: str
