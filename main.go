package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed static/*
var static embed.FS

var db *sql.DB

const (
	minAmount   = 1000.0
	maxAmount   = 50000.0
	minTerm     = 7
	maxTerm     = 30
	dailyRate   = 0.005 // 0.5% в день
	sessionLife = 7 * 24 * time.Hour
)

type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type Loan struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	UserEmail string     `json:"user_email,omitempty"`
	Amount    float64    `json:"amount"`
	TermDays  int        `json:"term_days"`
	TotalDue  float64    `json:"total_due"`
	Paid      float64    `json:"paid"`
	Status    string     `json:"status"` // pending, approved, rejected, repaid
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	DueDate   *time.Time `json:"due_date,omitempty"`

	FullName   string  `json:"full_name"`
	Phone      string  `json:"phone"`
	BirthDate  string  `json:"birth_date"`
	DocNumber  string  `json:"doc_number"`
	Address    string  `json:"address"`
	Employment string  `json:"employment"`
	Employer   string  `json:"employer"`
	Income     float64 `json:"income"`
	Purpose    string  `json:"purpose"`
}

type ctxKey struct{}

func main() {
	var err error
	db, err = sql.Open("sqlite", "file:credit.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	initDB()

	mux := http.NewServeMux()

	// фронтенд
	mux.Handle("GET /", http.FileServer(mustSub()))

	// авторизация
	mux.HandleFunc("POST /api/register", register)
	mux.HandleFunc("POST /api/login", login)
	mux.HandleFunc("POST /api/logout", auth("", logout))
	mux.HandleFunc("GET /api/me", auth("", me))

	// пользователь
	mux.HandleFunc("POST /api/loans", auth("", applyLoan))
	mux.HandleFunc("GET /api/loans", auth("", myLoans))
	mux.HandleFunc("POST /api/loans/{id}/repay", auth("", repayLoan))

	// админка
	mux.HandleFunc("GET /api/admin/loans", auth("admin", adminLoans))
	mux.HandleFunc("POST /api/admin/loans/{id}/approve", auth("admin", func(w http.ResponseWriter, r *http.Request) { decide(w, r, "approved") }))
	mux.HandleFunc("POST /api/admin/loans/{id}/reject", auth("admin", func(w http.ResponseWriter, r *http.Request) { decide(w, r, "rejected") }))

	// ВНИМАНИЕ: открытый API без авторизации — выдача роли пользователю
	mux.HandleFunc("PUT /api/users/{id}/role", setRole)

	log.Println("Сервер запущен: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func initDB() {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT UNIQUE NOT NULL,
	name TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'user',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(
	token TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id),
	expires_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS loans(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id),
	amount REAL NOT NULL,
	term_days INTEGER NOT NULL,
	total_due REAL NOT NULL,
	paid REAL NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'pending',
	created_at DATETIME NOT NULL,
	decided_at DATETIME,
	due_date DATETIME);`)
	if err != nil {
		log.Fatal(err)
	}
	// добавляем колонки анкеты (в том числе в уже существующую БД); ошибка "duplicate column" игнорируется
	for _, c := range []string{
		"full_name TEXT NOT NULL DEFAULT ''", "phone TEXT NOT NULL DEFAULT ''",
		"birth_date TEXT NOT NULL DEFAULT ''", "doc_number TEXT NOT NULL DEFAULT ''",
		"address TEXT NOT NULL DEFAULT ''", "employment TEXT NOT NULL DEFAULT ''",
		"employer TEXT NOT NULL DEFAULT ''", "income REAL NOT NULL DEFAULT 0",
		"purpose TEXT NOT NULL DEFAULT ''",
	} {
		db.Exec("ALTER TABLE loans ADD COLUMN " + c)
	}
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// auth: role "" — любой авторизованный, "admin" — только админ
func auth(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			fail(w, 401, "требуется авторизация")
			return
		}
		var u User
		err := db.QueryRow(`SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id
			WHERE s.token=? AND s.expires_at>?`, token, time.Now()).Scan(&u.ID, &u.Email, &u.Name, &u.Role)
		if err != nil {
			fail(w, 401, "неверный или просроченный токен")
			return
		}
		if role != "" && u.Role != role {
			fail(w, 403, "доступ запрещён")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}

func current(r *http.Request) User { return r.Context().Value(ctxKey{}).(User) }

func createSession(userID int64) string {
	t := newToken()
	db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)`, t, userID, time.Now().Add(sessionLife))
	return t
}

// ---------- auth ----------

func register(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Name, Password string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if _, err := mail.ParseAddress(in.Email); err != nil {
		fail(w, 400, "неверный email")
		return
	}
	if len(in.Password) < 6 || strings.TrimSpace(in.Name) == "" {
		fail(w, 400, "имя обязательно, пароль минимум 6 символов")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	res, err := db.Exec(`INSERT INTO users(email,name,password_hash) VALUES(?,?,?)`, in.Email, in.Name, string(hash))
	if err != nil {
		fail(w, 409, "email уже зарегистрирован")
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, 201, map[string]any{"id": id, "token": createSession(id)})
}

func login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	var id int64
	var hash string
	err := db.QueryRow(`SELECT id,password_hash FROM users WHERE email=?`, strings.ToLower(strings.TrimSpace(in.Email))).Scan(&id, &hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		fail(w, 401, "неверный email или пароль")
		return
	}
	writeJSON(w, 200, map[string]any{"token": createSession(id)})
}

func logout(w http.ResponseWriter, r *http.Request) {
	db.Exec(`DELETE FROM sessions WHERE token=?`, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func me(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, current(r)) }

// ---------- роли (без авторизации!) ----------

func setRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "неверный id")
		return
	}
	var in struct{ Role string }
	if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Role != "admin" && in.Role != "user") {
		fail(w, 400, `role должен быть "admin" или "user"`)
		return
	}
	res, _ := db.Exec(`UPDATE users SET role=? WHERE id=?`, in.Role, id)
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, 404, "пользователь не найден")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "role": in.Role})
}

// ---------- кредиты ----------

func scanLoans(rows *sql.Rows, withEmail bool) []Loan {
	defer rows.Close()
	out := []Loan{}
	for rows.Next() {
		var l Loan
		var email sql.NullString
		var dec, due sql.NullTime
		if rows.Scan(&l.ID, &l.UserID, &email, &l.Amount, &l.TermDays, &l.TotalDue, &l.Paid, &l.Status, &l.CreatedAt, &dec, &due,
			&l.FullName, &l.Phone, &l.BirthDate, &l.DocNumber, &l.Address, &l.Employment, &l.Employer, &l.Income, &l.Purpose) != nil {
			continue
		}
		if withEmail {
			l.UserEmail = email.String
		}
		if dec.Valid {
			l.DecidedAt = &dec.Time
		}
		if due.Valid {
			l.DueDate = &due.Time
		}
		out = append(out, l)
	}
	return out
}

const loanSelect = `SELECT l.id,l.user_id,u.email,l.amount,l.term_days,l.total_due,l.paid,l.status,l.created_at,l.decided_at,l.due_date,
	l.full_name,l.phone,l.birth_date,l.doc_number,l.address,l.employment,l.employer,l.income,l.purpose
	FROM loans l JOIN users u ON u.id=l.user_id `

func applyLoan(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	if u.Role == "admin" {
		fail(w, 403, "администратор не может брать кредиты")
		return
	}
	var in applyReq
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	if in.Amount < minAmount || in.Amount > maxAmount {
		fail(w, 400, "сумма должна быть от 1000 до 50000")
		return
	}
	if in.TermDays < minTerm || in.TermDays > maxTerm {
		fail(w, 400, "срок должен быть от 7 до 30 дней")
		return
	}
	if msg := in.validate(); msg != "" {
		fail(w, 400, msg)
		return
	}
	var active int
	db.QueryRow(`SELECT COUNT(*) FROM loans WHERE user_id=? AND status IN ('pending','approved')`, u.ID).Scan(&active)
	if active > 0 {
		fail(w, 409, "у вас уже есть активная заявка или непогашенный кредит")
		return
	}
	total := round2(in.Amount * (1 + dailyRate*float64(in.TermDays)))
	res, err := db.Exec(`INSERT INTO loans(user_id,amount,term_days,total_due,created_at,
		full_name,phone,birth_date,doc_number,address,employment,employer,income,purpose) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, in.Amount, in.TermDays, total, time.Now(),
		in.FullName, in.Phone, in.BirthDate, in.DocNumber, in.Address, in.Employment, in.Employer, in.Income, in.Purpose)
	if err != nil {
		fail(w, 500, "ошибка базы данных")
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, 201, map[string]any{"id": id, "total_due": total, "status": "pending"})
}

func myLoans(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(loanSelect+`WHERE l.user_id=? ORDER BY l.id DESC`, current(r).ID)
	if err != nil {
		fail(w, 500, "ошибка базы данных")
		return
	}
	writeJSON(w, 200, scanLoans(rows, false))
}

func repayLoan(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct{ Amount float64 }
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Amount <= 0 {
		fail(w, 400, "укажите сумму платежа")
		return
	}
	var total, paid float64
	var status string
	err := db.QueryRow(`SELECT total_due,paid,status FROM loans WHERE id=? AND user_id=?`, id, u.ID).Scan(&total, &paid, &status)
	if err != nil {
		fail(w, 404, "кредит не найден")
		return
	}
	if status != "approved" {
		fail(w, 409, "кредит не активен")
		return
	}
	remaining := round2(total - paid)
	if in.Amount > remaining {
		in.Amount = remaining
	}
	paid = round2(paid + in.Amount)
	if paid >= total {
		status = "repaid"
	}
	db.Exec(`UPDATE loans SET paid=?,status=? WHERE id=?`, paid, status, id)
	writeJSON(w, 200, map[string]any{"paid": paid, "remaining": round2(total - paid), "status": status})
}

// ---------- админ ----------

func adminLoans(w http.ResponseWriter, r *http.Request) {
	q, args := loanSelect, []any{}
	if s := r.URL.Query().Get("status"); s != "" {
		q += `WHERE l.status=? `
		args = append(args, s)
	}
	rows, err := db.Query(q+`ORDER BY l.id DESC`, args...)
	if err != nil {
		fail(w, 500, "ошибка базы данных")
		return
	}
	writeJSON(w, 200, scanLoans(rows, true))
}

func decide(w http.ResponseWriter, r *http.Request, status string) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	now := time.Now()
	var due any
	if status == "approved" {
		var term int
		if db.QueryRow(`SELECT term_days FROM loans WHERE id=?`, id).Scan(&term) == nil {
			due = now.AddDate(0, 0, term)
		}
	}
	res, _ := db.Exec(`UPDATE loans SET status=?,decided_at=?,due_date=? WHERE id=? AND status='pending'`, status, now, due, id)
	if n, _ := res.RowsAffected(); n == 0 {
		fail(w, 409, "заявка не найдена или уже обработана")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": status})
}

func mustSub() http.FileSystem {
	sub, err := fsSub()
	if err != nil {
		log.Fatal(err)
	}
	return http.FS(sub)
}

func fsSub() (fs.FS, error) { return fs.Sub(static, "static") }

// ---------- анкета заёмщика ----------

type applyReq struct {
	Amount     float64 `json:"amount"`
	TermDays   int     `json:"term_days"`
	FullName   string  `json:"full_name"`
	Phone      string  `json:"phone"`
	BirthDate  string  `json:"birth_date"`
	DocNumber  string  `json:"doc_number"`
	Address    string  `json:"address"`
	Employment string  `json:"employment"`
	Employer   string  `json:"employer"`
	Income     float64 `json:"income"`
	Purpose    string  `json:"purpose"`
	Consent    bool    `json:"consent"`
}

// validate проверяет анкету и возвращает текст ошибки (пустая строка — всё ок)
func (a *applyReq) validate() string {
	for _, p := range []*string{&a.FullName, &a.Phone, &a.BirthDate, &a.DocNumber, &a.Address, &a.Employment, &a.Employer, &a.Purpose} {
		*p = strings.TrimSpace(*p)
	}
	if len(strings.Fields(a.FullName)) < 2 {
		return "укажите ФИО полностью (минимум фамилия и имя)"
	}
	digits := 0
	for _, c := range a.Phone {
		if c >= '0' && c <= '9' {
			digits++
		} else if !strings.ContainsRune("+-() ", c) {
			return "неверный формат телефона"
		}
	}
	if digits < 10 || digits > 15 {
		return "неверный номер телефона"
	}
	bd, err := time.Parse("2006-01-02", a.BirthDate)
	if err != nil {
		return "укажите дату рождения"
	}
	if bd.AddDate(18, 0, 0).After(time.Now()) {
		return "кредит выдаётся только совершеннолетним (с 18 лет)"
	}
	if bd.Year() < time.Now().Year()-100 {
		return "неверная дата рождения"
	}
	if n := utf8.RuneCountInString(a.DocNumber); n < 6 || n > 20 {
		return "номер документа: от 6 до 20 символов"
	}
	if utf8.RuneCountInString(a.Address) < 5 {
		return "укажите адрес проживания"
	}
	switch a.Employment {
	case "employed":
		if a.Employer == "" {
			return "укажите работодателя"
		}
	case "self", "student", "pensioner", "unemployed":
		a.Employer = ""
	default:
		return "неверный статус занятости"
	}
	if a.Income <= 0 {
		return "укажите ежемесячный доход"
	}
	if utf8.RuneCountInString(a.Purpose) < 3 {
		return "укажите цель займа"
	}
	if !a.Consent {
		return "необходимо согласие на обработку данных"
	}
	return ""
}
