from pydantic import BaseModel


class OSVMinimalVuln(BaseModel):
    id: str
    modified: str


class OSVBatchResult(BaseModel):
    vulns: list[OSVMinimalVuln] = []


class OSVEvent(BaseModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


class OSVRange(BaseModel):
    type: str
    repo: str | None = None
    events: list[OSVEvent] = []


class OSVPackage(BaseModel):
    name: str
    ecosystem: str
    purl: str | None = None


class OSVAffected(BaseModel):
    package: OSVPackage | None = None
    ranges: list[OSVRange] = []
    versions: list[str] = []


class OSVReference(BaseModel):
    type: str
    url: str


class OSVSeverity(BaseModel):
    type: str
    score: str


class OSVVulnerability(BaseModel):
    id: str
    summary: str = ""
    details: str = ""
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    aliases: list[str] = []
    affected: list[OSVAffected] = []
    references: list[OSVReference] = []
    severity: list[OSVSeverity] = []
