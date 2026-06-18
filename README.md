# MEROS AI — Oilaning Umrbod Raqamli Hamrohi

## Ishga tushirish

### Backend
```bash
cd backend
python3 app.py
# → http://localhost:5050
```

### Frontend
```bash
cd frontend
python3 -m http.server 3000
# → http://localhost:3000
```

### Demo login
- Telefon: `+998901234567`
- Parol: `demo123`

## API Endpointlar

| Method | Endpoint | Tavsif |
|--------|----------|--------|
| POST | /api/auth/login | Kirish |
| POST | /api/auth/register | Ro'yxatdan o'tish |
| POST | /api/auth/send-otp | OTP yuborish |
| POST | /api/auth/verify-otp | OTP tasdiqlash |
| GET  | /api/dashboard | Bosh sahifa ma'lumotlari |
| GET  | /api/family | Oila va a'zolar |
| POST | /api/family/members | A'zo qo'shish |
| GET  | /api/health/vaccines | Emlash jadvali |
| POST | /api/health/vaccines | Emlash qo'shish |
| PATCH| /api/health/vaccines/:id/complete | Bajarildi belgilash |
| GET  | /api/health/records | Tibbiy yozuvlar |
| POST | /api/health/records | Yozuv qo'shish |
| GET  | /api/memories | Xotiralar |
| POST | /api/memories | Xotira qo'shish |
| DELETE| /api/memories/:id | O'chirish |
| GET  | /api/capsules | Vaqt kapsulalari |
| POST | /api/capsules | Kapsula yaratish |
| PATCH| /api/capsules/:id/open | Ochish |
| GET  | /api/warmth | Issiqlik o'lchovi |
| POST | /api/warmth | Ball kiritish |
| GET  | /api/alerts | Ogohlantirishlar |
| PATCH| /api/alerts/:id/read | O'qildi |

## Stack
- **Backend**: Python Flask + SQLite
- **Frontend**: HTML/CSS/JS (vanilla, framework siz)
- **Auth**: JWT tokens
- **DB**: SQLite (prod uchun PostgreSQL)
