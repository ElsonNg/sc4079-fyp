from shared.metadata import AdvisoryDetails, SourceReference
from shared.records import MetadataRecord


class RetrievalMatch(MetadataRecord):
    advisory: AdvisoryDetails
    origin: SourceReference

    similarity: float = 0.0
