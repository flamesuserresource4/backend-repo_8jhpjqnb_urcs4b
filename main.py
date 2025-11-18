import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal, Any, Dict

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr

from database import db, create_document, get_documents
from bson import ObjectId

# -----------------------------
# App and Security Config
# -----------------------------
app = FastAPI(title="Anime API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# -----------------------------
# Helpers
# -----------------------------

def to_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc["id"] = str(doc.pop("_id"))
    return doc


# -----------------------------
# Schemas (request/response)
# -----------------------------
class SignupRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=6)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    username: str
    role: Literal["user", "admin"]
    avatar_url: Optional[str] = None
    bio: Optional[str] = None


class UserUpdate(BaseModel):
    avatar_url: Optional[str] = None
    bio: Optional[str] = None


class GenreCreate(BaseModel):
    name: str
    slug: str


class TagCreate(BaseModel):
    name: str
    slug: str


class AnimeCreate(BaseModel):
    title: str
    alt_titles: Optional[List[str]] = None
    synopsis: Optional[str] = None
    year: Optional[int] = None
    type: Optional[Literal["TV", "Movie", "OVA", "ONA"]] = None
    status: Optional[Literal["ongoing", "completed", "hiatus"]] = None
    poster_url: Optional[str] = None
    banner_url: Optional[str] = None
    studio_id: Optional[str] = None
    source: Optional[Literal["original", "manga", "light_novel", "game"]] = None
    genre_ids: Optional[List[str]] = None
    tag_ids: Optional[List[str]] = None


class AnimeUpdate(BaseModel):
    title: Optional[str] = None
    alt_titles: Optional[List[str]] = None
    synopsis: Optional[str] = None
    year: Optional[int] = None
    type: Optional[Literal["TV", "Movie", "OVA", "ONA"]] = None
    status: Optional[Literal["ongoing", "completed", "hiatus"]] = None
    poster_url: Optional[str] = None
    banner_url: Optional[str] = None
    studio_id: Optional[str] = None
    source: Optional[Literal["original", "manga", "light_novel", "game"]] = None
    genre_ids: Optional[List[str]] = None
    tag_ids: Optional[List[str]] = None


class ReviewCreate(BaseModel):
    rating: int = Field(ge=1, le=10)
    title: Optional[str] = None
    body: Optional[str] = None


class CommentCreate(BaseModel):
    body: str
    parent_id: Optional[str] = None
    episode_id: Optional[str] = None


class WatchlistCreate(BaseModel):
    anime_id: str
    status: Literal["planned", "watching", "completed", "dropped"] = "planned"


# -----------------------------
# Auth dependencies
# -----------------------------
async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.user.find_one({"_id": to_object_id(user_id)})
    if not user:
        raise credentials_exception
    return serialize_doc(user)


def require_admin(user: Dict[str, Any] = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# -----------------------------
# Basic routes
# -----------------------------
@app.get("/")
def root():
    return {"message": "Anime API running"}


@app.get("/test")
def test_database():
    status_msg = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            status_msg["database"] = "✅ Connected"
            status_msg["connection_status"] = "Connected"
            status_msg["collections"] = db.list_collection_names()[:10]
        else:
            status_msg["database"] = "❌ Not Available"
    except Exception as e:
        status_msg["database"] = f"⚠️ Error: {str(e)[:80]}"
    return status_msg


# -----------------------------
# Auth endpoints
# -----------------------------
@app.post("/auth/signup", response_model=UserPublic, status_code=201)
def signup(payload: SignupRequest):
    if db.user.find_one({"$or": [{"email": payload.email}, {"username": payload.username}] }):
        raise HTTPException(status_code=400, detail="Email or username already in use")
    doc = {
        "email": payload.email,
        "username": payload.username,
        "password_hash": hash_password(payload.password),
        "role": "user",
        "avatar_url": None,
        "bio": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db.user.insert_one(doc)
    doc["_id"] = result.inserted_id
    ser = serialize_doc(doc)
    return {
        "id": ser["id"],
        "email": ser["email"],
        "username": ser["username"],
        "role": ser["role"],
        "avatar_url": ser.get("avatar_url"),
        "bio": ser.get("bio"),
    }


@app.post("/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # OAuth2PasswordRequestForm sends username field which we'll map to email or username
    user_doc = db.user.find_one({"$or": [{"email": form_data.username}, {"username": form_data.username}]})
    if not user_doc or not verify_password(form_data.password, user_doc.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token({"sub": str(user_doc["_id"])})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me", response_model=UserPublic)
def me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "username": current_user["username"],
        "role": current_user.get("role", "user"),
        "avatar_url": current_user.get("avatar_url"),
        "bio": current_user.get("bio"),
    }


@app.patch("/me", response_model=UserPublic)
def update_me(update: UserUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    update_dict = {k: v for k, v in update.model_dump(exclude_none=True).items()}
    update_dict["updated_at"] = datetime.now(timezone.utc)
    db.user.update_one({"_id": to_object_id(current_user["id"])}, {"$set": update_dict})
    fresh = db.user.find_one({"_id": to_object_id(current_user["id"])})
    fresh = serialize_doc(fresh)
    return {
        "id": fresh["id"],
        "email": fresh["email"],
        "username": fresh["username"],
        "role": fresh.get("role", "user"),
        "avatar_url": fresh.get("avatar_url"),
        "bio": fresh.get("bio"),
    }


# -----------------------------
# Genres & Tags
# -----------------------------
@app.get("/genres")
def list_genres():
    items = [serialize_doc(x) for x in db.genre.find({}).sort("name", 1)]
    return {"items": items, "total": len(items)}


@app.post("/genres", status_code=201)
def create_genre(payload: GenreCreate, _: Dict[str, Any] = Depends(require_admin)):
    if db.genre.find_one({"$or": [{"name": payload.name}, {"slug": payload.slug}] }):
        raise HTTPException(status_code=400, detail="Genre already exists")
    payload_dict = payload.model_dump()
    payload_dict["created_at"] = datetime.now(timezone.utc)
    payload_dict["updated_at"] = datetime.now(timezone.utc)
    res = db.genre.insert_one(payload_dict)
    return serialize_doc({"_id": res.inserted_id, **payload_dict})


@app.get("/tags")
def list_tags():
    items = [serialize_doc(x) for x in db.tag.find({}).sort("name", 1)]
    return {"items": items, "total": len(items)}


@app.post("/tags", status_code=201)
def create_tag(payload: TagCreate, _: Dict[str, Any] = Depends(require_admin)):
    if db.tag.find_one({"$or": [{"name": payload.name}, {"slug": payload.slug}] }):
        raise HTTPException(status_code=400, detail="Tag already exists")
    payload_dict = payload.model_dump()
    payload_dict["created_at"] = datetime.now(timezone.utc)
    payload_dict["updated_at"] = datetime.now(timezone.utc)
    res = db.tag.insert_one(payload_dict)
    return serialize_doc({"_id": res.inserted_id, **payload_dict})


# -----------------------------
# Anime CRUD + listing
# -----------------------------
@app.get("/anime")
def list_anime(
    q: Optional[str] = None,
    genre: Optional[str] = None,  # genre id
    tag: Optional[str] = None,    # tag id
    year_from: Optional[int] = None,
    year_to: Optional[int] = None,
    sort: Optional[str] = None,  # popularity|rating|latest
    page: int = 1,
    page_size: int = 20,
):
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 20

    query: Dict[str, Any] = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"alt_titles": {"$elemMatch": {"$regex": q, "$options": "i"}}},
        ]
    if genre:
        query["genre_ids"] = genre
    if tag:
        query["tag_ids"] = tag
    if year_from or year_to:
        query["year"] = {}
        if year_from:
            query["year"]["$gte"] = year_from
        if year_to:
            query["year"]["$lte"] = year_to

    sort_spec = None
    if sort == "popularity":
        sort_spec = [("popularity", -1)]
    elif sort == "rating":
        sort_spec = [("average_rating", -1)]
    elif sort == "latest":
        sort_spec = [("created_at", -1)]

    total = db.anime.count_documents(query)
    cursor = db.anime.find(query)
    if sort_spec:
        cursor = cursor.sort(sort_spec)
    cursor = cursor.skip((page - 1) * page_size).limit(page_size)

    items = [serialize_doc(x) for x in cursor]
    return {"items": items, "page": page, "pageSize": page_size, "total": total, "totalPages": (total + page_size - 1)//page_size}


@app.get("/anime/trending")
def trending():
    cursor = db.anime.find({}).sort([("popularity", -1)]).limit(12)
    return {"items": [serialize_doc(x) for x in cursor]}


@app.get("/anime/{anime_id}")
def get_anime(anime_id: str):
    doc = db.anime.find_one({"_id": to_object_id(anime_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Anime not found")
    anime = serialize_doc(doc)
    # include genres/tags expanded
    if anime.get("genre_ids"):
        genres = list(db.genre.find({"_id": {"$in": [to_object_id(g) for g in anime["genre_ids"]]}}))
        anime["genres"] = [{"id": str(g["_id"]), "name": g["name"], "slug": g["slug"]} for g in genres]
    if anime.get("tag_ids"):
        tags = list(db.tag.find({"_id": {"$in": [to_object_id(t) for t in anime["tag_ids"]]}}))
        anime["tags"] = [{"id": str(t["_id"]), "name": t["name"], "slug": t["slug"]} for t in tags]
    return anime


@app.post("/anime", status_code=201)
def create_anime(payload: AnimeCreate, _: Dict[str, Any] = Depends(require_admin)):
    data = payload.model_dump()
    data.update({
        "popularity": 0,
        "average_rating": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    res = db.anime.insert_one(data)
    data["_id"] = res.inserted_id
    return serialize_doc(data)


@app.patch("/anime/{anime_id}")
def update_anime(anime_id: str, payload: AnimeUpdate, _: Dict[str, Any] = Depends(require_admin)):
    update = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    update["updated_at"] = datetime.now(timezone.utc)
    result = db.anime.update_one({"_id": to_object_id(anime_id)}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Anime not found")
    doc = db.anime.find_one({"_id": to_object_id(anime_id)})
    return serialize_doc(doc)


@app.delete("/anime/{anime_id}", status_code=204)
def delete_anime(anime_id: str, _: Dict[str, Any] = Depends(require_admin)):
    result = db.anime.delete_one({"_id": to_object_id(anime_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Anime not found")
    return


# -----------------------------
# Episodes (basic read; admin CRUD optional)
# -----------------------------
@app.get("/anime/{anime_id}/episodes")
def list_episodes(anime_id: str, page: int = 1, page_size: int = 30):
    q = {"anime_id": anime_id}
    total = db.episode.count_documents(q)
    cursor = db.episode.find(q).sort([("number", 1)]).skip((page-1)*page_size).limit(page_size)
    return {"items": [serialize_doc(x) for x in cursor], "total": total, "page": page, "pageSize": page_size}


# -----------------------------
# Reviews and Ratings
# -----------------------------
@app.get("/anime/{anime_id}/reviews")
def get_reviews(anime_id: str):
    items = [serialize_doc(x) for x in db.review.find({"anime_id": anime_id}).sort([("created_at", -1)])]
    return {"items": items, "total": len(items)}


@app.post("/anime/{anime_id}/reviews", status_code=201)
def create_or_update_review(anime_id: str, payload: ReviewCreate, user: Dict[str, Any] = Depends(get_current_user)):
    existing = db.review.find_one({"anime_id": anime_id, "user_id": user["id"]})
    now = datetime.now(timezone.utc)
    if existing:
        db.review.update_one({"_id": existing["_id"]}, {"$set": {"rating": payload.rating, "title": payload.title, "body": payload.body, "updated_at": now}})
    else:
        db.review.insert_one({"anime_id": anime_id, "user_id": user["id"], "rating": payload.rating, "title": payload.title, "body": payload.body, "created_at": now, "updated_at": now})
    # recompute average rating
    agg = list(db.review.aggregate([
        {"$match": {"anime_id": anime_id}},
        {"$group": {"_id": "$anime_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
    ]))
    if agg:
        db.anime.update_one({"_id": to_object_id(anime_id)}, {"$set": {"average_rating": round(float(agg[0]["avg"]), 2)}})
    doc = db.review.find_one({"anime_id": anime_id, "user_id": user["id"]})
    return serialize_doc(doc)


# -----------------------------
# Comments (flat/threaded basic)
# -----------------------------
@app.get("/anime/{anime_id}/comments")
def list_comments(anime_id: str):
    items = [serialize_doc(x) for x in db.comment.find({"anime_id": anime_id}).sort([("created_at", 1)])]
    return {"items": items, "total": len(items)}


@app.post("/anime/{anime_id}/comments", status_code=201)
def create_comment(anime_id: str, payload: CommentCreate, user: Dict[str, Any] = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    doc = {
        "anime_id": anime_id,
        "episode_id": payload.episode_id,
        "user_id": user["id"],
        "body": payload.body,
        "parent_id": payload.parent_id,
        "created_at": now,
        "updated_at": now,
    }
    res = db.comment.insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)


# -----------------------------
# Watchlist
# -----------------------------
@app.get("/me/watchlist")
def my_watchlist(user: Dict[str, Any] = Depends(get_current_user)):
    items = [serialize_doc(x) for x in db.watchlist.find({"user_id": user["id"]}).sort([("updated_at", -1)])]
    return {"items": items, "total": len(items)}


@app.post("/watchlist", status_code=201)
def add_to_watchlist(payload: WatchlistCreate, user: Dict[str, Any] = Depends(get_current_user)):
    existing = db.watchlist.find_one({"user_id": user["id"], "anime_id": payload.anime_id})
    now = datetime.now(timezone.utc)
    if existing:
        db.watchlist.update_one({"_id": existing["_id"]}, {"$set": {"status": payload.status, "updated_at": now}})
        doc = db.watchlist.find_one({"_id": existing["_id"]})
    else:
        doc = {"user_id": user["id"], "anime_id": payload.anime_id, "status": payload.status, "created_at": now, "updated_at": now}
        res = db.watchlist.insert_one(doc)
        doc["_id"] = res.inserted_id
    return serialize_doc(doc)


@app.patch("/watchlist/{item_id}")
def update_watchlist(item_id: str, status_value: Literal["planned", "watching", "completed", "dropped"] = Body(..., embed=True, alias="status"), user: Dict[str, Any] = Depends(get_current_user)):
    result = db.watchlist.update_one({"_id": to_object_id(item_id), "user_id": user["id"]}, {"$set": {"status": status_value, "updated_at": datetime.now(timezone.utc)}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    doc = db.watchlist.find_one({"_id": to_object_id(item_id)})
    return serialize_doc(doc)


@app.delete("/watchlist/{item_id}", status_code=204)
def remove_watchlist(item_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    result = db.watchlist.delete_one({"_id": to_object_id(item_id), "user_id": user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    return


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
