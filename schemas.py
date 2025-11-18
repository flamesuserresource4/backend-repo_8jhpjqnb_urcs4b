"""
Database Schemas for Anime Website (MongoDB)

Each Pydantic model corresponds to a collection. The collection name is the
lowercased class name (e.g., User -> "user").

We store references via ObjectId strings.
"""

from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr

# Core user schema
class User(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30)
    password_hash: str = Field(..., description="BCrypt hash")
    role: Literal["user", "admin"] = "user"
    avatar_url: Optional[str] = None
    bio: Optional[str] = None

# Taxonomy
class Genre(BaseModel):
    name: str
    slug: str

class Tag(BaseModel):
    name: str
    slug: str

class Studio(BaseModel):
    name: str
    website: Optional[str] = None
    country: Optional[str] = None

# Anime and related
class Anime(BaseModel):
    title: str
    alt_titles: Optional[List[str]] = None
    synopsis: Optional[str] = None
    year: Optional[int] = None
    type: Optional[Literal["TV", "Movie", "OVA", "ONA"]] = None
    status: Optional[Literal["ongoing", "completed", "hiatus"]] = None
    popularity: int = 0
    average_rating: float = 0
    poster_url: Optional[str] = None
    banner_url: Optional[str] = None
    studio_id: Optional[str] = None
    source: Optional[Literal["original", "manga", "light_novel", "game"]] = None
    genre_ids: Optional[List[str]] = None
    tag_ids: Optional[List[str]] = None
    metadata: Optional[dict] = None  # External IDs

class Episode(BaseModel):
    anime_id: str
    number: int
    title: Optional[str] = None
    synopsis: Optional[str] = None
    air_date: Optional[str] = None
    duration_minutes: Optional[int] = None
    thumbnail_url: Optional[str] = None
    video_manifest_url: Optional[str] = None

class Review(BaseModel):
    anime_id: str
    user_id: str
    rating: int = Field(..., ge=1, le=10)
    title: Optional[str] = None
    body: Optional[str] = None

class Comment(BaseModel):
    anime_id: Optional[str] = None
    episode_id: Optional[str] = None
    user_id: str
    body: str
    parent_id: Optional[str] = None

class Watchlist(BaseModel):
    user_id: str
    anime_id: str
    status: Literal["planned", "watching", "completed", "dropped"] = "planned"
