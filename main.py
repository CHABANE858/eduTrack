from fastapi import FastAPI, HTTPException, Depends, status

from fastapi.staticfiles import StaticFiles

from fastapi.responses import FileResponse

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel

from typing import Optional, List

from motor.motor_asyncio import AsyncIOMotorClient

from bson import ObjectId

from datetime import datetime, date

import os, hashlib, secrets


app = FastAPI(title="EduTrack API")


MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")

client = AsyncIOMotorClient(MONGO_URL)

db = client.edutrack


users_col     = db.users

students_col  = db.students

courses_col   = db.courses

attendance_col = db.attendance


app.mount("/static", StaticFiles(directory="static"), name="static")

security = HTTPBearer(auto_error=False)

tokens: dict = {}


# --- Helpers ---

def sid(doc) -> dict:

    doc["id"] = str(doc.pop("_id"))

    return doc


def hash_pw(pw: str) -> str:

    return hashlib.sha256(pw.encode()).hexdigest()


# --- Models ---

class LoginRequest(BaseModel):

    username: str

    password: str


class UserCreate(BaseModel):

    username: str

    password: str

    full_name: str

    role: str


class StudentCreate(BaseModel):

    first_name: str

    last_name: str

    email: str

    student_id: str

    birth_date: Optional[str] = ""

    phone: Optional[str] = ""


class StudentUpdate(BaseModel):

    first_name: Optional[str] = None

    last_name: Optional[str] = None

    email: Optional[str] = None

    phone: Optional[str] = None


class CourseCreate(BaseModel):

    name: str

    code: str

    professor_id: str

    schedule: Optional[str] = ""


class AttendanceRecord(BaseModel):

    student_id: str

    course_id: str

    date: str

    status: str  # present | absent | late


# --- Auth ---

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):

    if not credentials:

        raise HTTPException(status_code=401, detail="Non authentifié")

    user_id = tokens.get(credentials.credentials)

    if not user_id:

        raise HTTPException(status_code=401, detail="Token invalide")

    user = await users_col.find_one({"_id": ObjectId(user_id)})

    if not user:

        raise HTTPException(status_code=401, detail="Introuvable")

    return sid(user)


async def require_admin(user=Depends(get_current_user)):

    if user["role"] != "admin":

        raise HTTPException(status_code=403, detail="Réservé aux admins")

    return user


# --- Routes ---

@app.get("/")

async def root():

    return FileResponse("static/index.html")


@app.post("/api/auth/login")

async def login(req: LoginRequest):

    user = await users_col.find_one({"username": req.username, "password": hash_pw(req.password)})

    if not user:

        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    token = secrets.token_hex(32)

    tokens[token] = str(user["_id"])

    return {"token": token, "user": {"id": str(user["_id"]), "username": user["username"], "full_name": user["full_name"], "role": user["role"]}}


@app.post("/api/auth/logout")

async def logout(user=Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):

    tokens.pop(credentials.credentials, None)

    return {"ok": True}


@app.get("/api/auth/me")

async def me(user=Depends(get_current_user)):

    return user


# Users

@app.get("/api/users")

async def get_users(admin=Depends(require_admin)):

    users = await users_col.find({}, {"password": 0}).to_list(100)

    return [sid(u) for u in users]


@app.post("/api/users", status_code=201)

async def create_user(user: UserCreate, admin=Depends(require_admin)):

    if await users_col.find_one({"username": user.username}):

        raise HTTPException(400, "Nom d'utilisateur déjà pris")

    doc = {**user.dict(), "password": hash_pw(user.password), "created_at": datetime.utcnow().isoformat()}

    result = await users_col.insert_one(doc)

    created = await users_col.find_one({"_id": result.inserted_id}, {"password": 0})

    return sid(created)


@app.delete("/api/users/{user_id}", status_code=204)

async def delete_user(user_id: str, admin=Depends(require_admin)):

    await users_col.delete_one({"_id": ObjectId(user_id)})


# Students

@app.get("/api/students")

async def get_students(user=Depends(get_current_user)):

    students = await students_col.find().sort("last_name", 1).to_list(500)

    return [sid(s) for s in students]


@app.post("/api/students", status_code=201)

async def create_student(student: StudentCreate, admin=Depends(require_admin)):

    if await students_col.find_one({"student_id": student.student_id}):

        raise HTTPException(400, "Numéro étudiant déjà existant")

    doc = {**student.dict(), "created_at": datetime.utcnow().isoformat()}

    result = await students_col.insert_one(doc)

    created = await students_col.find_one({"_id": result.inserted_id})

    return sid(created)


@app.patch("/api/students/{student_id}")

async def update_student(student_id: str, data: StudentUpdate, admin=Depends(require_admin)):

    updates = {k: v for k, v in data.dict().items() if v is not None}

    await students_col.update_one({"_id": ObjectId(student_id)}, {"$set": updates})

    return sid(await students_col.find_one({"_id": ObjectId(student_id)}))


@app.delete("/api/students/{student_id}", status_code=204)

async def delete_student(student_id: str, admin=Depends(require_admin)):

    await students_col.delete_one({"_id": ObjectId(student_id)})


# Courses

@app.get("/api/courses")

async def get_courses(user=Depends(get_current_user)):

    courses = await courses_col.find().to_list(200)

    result = []

    for c in courses:

        c = sid(c)

        prof = await users_col.find_one({"_id": ObjectId(c["professor_id"])}, {"password": 0}) if c.get("professor_id") else None

        c["professor_name"] = prof["full_name"] if prof else "—"

        result.append(c)

    return result


@app.post("/api/courses", status_code=201)

async def create_course(course: CourseCreate, admin=Depends(require_admin)):

    doc = {**course.dict(), "created_at": datetime.utcnow().isoformat()}

    result = await courses_col.insert_one(doc)

    return sid(await courses_col.find_one({"_id": result.inserted_id}))


@app.delete("/api/courses/{course_id}", status_code=204)

async def delete_course(course_id: str, admin=Depends(require_admin)):

    await courses_col.delete_one({"_id": ObjectId(course_id)})


# Attendance

@app.get("/api/attendance")

async def get_attendance(course_id: Optional[str] = None, date_str: Optional[str] = None, user=Depends(get_current_user)):

    query = {}

    if course_id: query["course_id"] = course_id

    if date_str:  query["date"] = date_str

    records = await attendance_col.find(query).to_list(1000)

    return [sid(r) for r in records]


@app.post("/api/attendance", status_code=201)

async def save_attendance(record: AttendanceRecord, user=Depends(get_current_user)):

    existing = await attendance_col.find_one({"student_id": record.student_id, "course_id": record.course_id, "date": record.date})

    if existing:

        await attendance_col.update_one({"_id": existing["_id"]}, {"$set": {"status": record.status}})

        return sid(await attendance_col.find_one({"_id": existing["_id"]}))

    doc = {**record.dict(), "recorded_by": user["id"], "created_at": datetime.utcnow().isoformat()}

    result = await attendance_col.insert_one(doc)

    return sid(await attendance_col.find_one({"_id": result.inserted_id}))


@app.get("/api/attendance/stats/{student_id}")

async def attendance_stats(student_id: str, user=Depends(get_current_user)):

    records = await attendance_col.find({"student_id": student_id}).to_list(1000)

    total = len(records)

    present = sum(1 for r in records if r["status"] == "present")

    absent  = sum(1 for r in records if r["status"] == "absent")

    late    = sum(1 for r in records if r["status"] == "late")

    return {"total": total, "present": present, "absent": absent, "late": late,

            "rate": round((present / total * 100) if total else 0, 1)}


@app.get("/api/stats")

async def dashboard_stats(user=Depends(get_current_user)):

    today = date.today().isoformat()

    return {

        "total_students":   await students_col.count_documents({}),

        "total_courses":    await courses_col.count_documents({}),

        "total_professors": await users_col.count_documents({"role": "professor"}),

        "today_present":    await attendance_col.count_documents({"date": today, "status": "present"}),

        "today_absent":     await attendance_col.count_documents({"date": today, "status": "absent"}),

    }


@app.on_event("startup")

async def seed():

    if not await users_col.find_one({"username": "admin"}):

        await users_col.insert_one({"username": "admin", "password": hash_pw("admin123"),

            "full_name": "Fayad", "role": "admin", "created_at": datetime.utcnow().isoformat()})

        print("✅ Admin créé : admin / admin123")
