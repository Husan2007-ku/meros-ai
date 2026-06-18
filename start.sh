#!/bin/bash
# MEROS AI — Ishga tushirish skripti

echo ""
echo "╔══════════════════════════════════════╗"
echo "║        MEROS AI  v1.0                ║"
echo "║   Oilaning Umrbod Raqamli Hamrohi    ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Backend ishga tushirish
echo "▶ Backend ishga tushmoqda (port 5050)..."
cd "$(dirname "$0")/backend"
python3 app.py &
BACKEND_PID=$!

sleep 1

# Frontend server (oddiy HTTP server)
echo "▶ Frontend server ishga tushmoqda (port 3000)..."
cd "$(dirname "$0")/frontend"
python3 -m http.server 3000 --bind 0.0.0.0 &
FRONTEND_PID=$!

sleep 1

echo ""
echo "✅ MEROS AI muvaffaqiyatli ishga tushdi!"
echo ""
echo "   🌐 Ilova:   http://localhost:3000"
echo "   ⚙️  API:     http://localhost:5050/api"
echo "   📊 Health:  http://localhost:5050/api/health"
echo ""
echo "   Demo hisob:"
echo "   📱 Telefon: +998901234567"
echo "   🔑 Parol:   demo123"
echo ""
echo "   Dasturni to'xtatish uchun: Ctrl+C"
echo ""

# Kutish
wait $BACKEND_PID $FRONTEND_PID
