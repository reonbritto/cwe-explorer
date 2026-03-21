from pydantic import BaseModel
from typing import List, Optional


class CWEEntry(BaseModel):
    id: str
    name: str
    description: str


class CVSSScores(BaseModel):
    v2_score: Optional[float] = None
    v2_vector: Optional[str] = None
    v3_score: Optional[float] = None
    v3_vector: Optional[str] = None
    v3_severity: Optional[str] = None


class AffectedProduct(BaseModel):
    vendor: str
    product: str
    version: str


class Reference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: List[str] = []


class CVEDetail(BaseModel):
    cve_id: str
    description: str
    cvss: CVSSScores
    cwe_ids: List[str] = []
    references: List[Reference] = []
    affected_products: List[AffectedProduct] = []
    published: str
    modified: str


class CVESearchResult(BaseModel):
    cve_id: str
    description: str
    severity: Optional[str] = None
    cvss_v3: Optional[float] = None
    published: str


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0


class CWEStats(BaseModel):
    cwe_id: str
    cwe_name: str
    cve_count: int


class TrendPoint(BaseModel):
    year: int
    severity: str
    count: int
