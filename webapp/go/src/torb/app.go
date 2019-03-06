package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"
	"net/http"
	_ "net/http/pprof"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"

	"sync"
	"math/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

type User struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
}

type Event struct {
	ID       int64  `json:"id,omitempty"`
	Title    string `json:"title,omitempty"`
	PublicFg bool   `json:"public,omitempty"`
	ClosedFg bool   `json:"closed,omitempty"`
	Price    int64  `json:"price,omitempty"`

	Total   int                `json:"total"`
	Remains int                `json:"remains"`
	Sheets  map[string]*Sheets `json:"sheets,omitempty"`
}

type Sheets struct {
	Total   int      `json:"total"`
	Remains int      `json:"remains"`
	Detail  []*Sheet `json:"detail,omitempty"`
	Price   int64    `json:"price"`
}

type Sheet struct {
	ID    int64  `json:"-"`
	Rank  string `json:"-"`
	Num   int64  `json:"num"`
	Price int64  `json:"-"`

	Mine           bool       `json:"mine,omitempty"`
	User					 int64			`json:"user,omitempty"`
	Reserved       bool       `json:"reserved,omitempty"`
	ReservedAt     *time.Time `json:"-"`
	ReservedAtUnix int64      `json:"reserved_at,omitempty"`
}

type Reservation struct {
	ID         int64      `json:"id"`
	EventID    int64      `json:"-"`
	SheetID    int64      `json:"-"`
	UserID     int64      `json:"-"`
	ReservedAt *time.Time `json:"-"`
	CanceledAt *time.Time `json:"-"`

	Event          *Event `json:"event,omitempty"`
	SheetRank      string `json:"sheet_rank,omitempty"`
	SheetNum       int64  `json:"sheet_num,omitempty"`
	Price          int64  `json:"price,omitempty"`
	ReservedAtUnix int64  `json:"reserved_at,omitempty"`
	CanceledAtUnix int64  `json:"canceled_at,omitempty"`
}

type Administrator struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
}

func sessUserID(c echo.Context) (int64, string) {
	sess, _ := session.Get("session", c)
	var userID int64
	var nickname string
	if x, ok := sess.Values["user_id"]; ok {
		userID, _ = x.(int64)
	}
	if x, ok := sess.Values["nickname"]; ok {
		nickname, _ = x.(string)
	}
	return userID, nickname
}

func sessSetUserID(c echo.Context, id int64, nickname string) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	sess.Values["user_id"] = id
	sess.Values["nickname"] = nickname
	sess.Save(c.Request(), c.Response())
}

func sessDeleteUserID(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	delete(sess.Values, "user_id")
	delete(sess.Values, "nickname")
	sess.Save(c.Request(), c.Response())
}

func sessAdministratorID(c echo.Context) (int64, string) {
	sess, _ := session.Get("session", c)
	var administratorID int64
	var administratorNickname string
	if x, ok := sess.Values["administrator_id"]; ok {
		administratorID, _ = x.(int64)
	}
	if x, ok := sess.Values["administrator_nickname"]; ok {
		administratorNickname, _ = x.(string)
	}
	return administratorID, administratorNickname
}

func sessSetAdministratorID(c echo.Context, id int64, nickname string) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	sess.Values["administrator_id"] = id
	sess.Values["administrator_nickname"] = nickname
	sess.Save(c.Request(), c.Response())
}

func sessDeleteAdministratorID(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	delete(sess.Values, "administrator_id")
	delete(sess.Values, "administrator_nickname")
	sess.Save(c.Request(), c.Response())
}

func loginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, err := getLoginUser(c); err != nil {
			return resError(c, "login_required", 401)
		}
		return next(c)
	}
}

func adminLoginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, err := getLoginAdministrator(c); err != nil {
			return resError(c, "admin_login_required", 401)
		}
		return next(c)
	}
}

func getLoginUser(c echo.Context) (*User, error) {
	userID, nickname := sessUserID(c)
	if userID == 0 {
		return nil, errors.New("not logged in")
	}
	return &User{ID: userID, Nickname: nickname}, nil
}

func getLoginAdministrator(c echo.Context) (*Administrator, error) {
	administratorID, administratorNickname := sessAdministratorID(c)
	if administratorID == 0 {
		return nil, errors.New("not logged in")
	}
	return &Administrator{ID: administratorID, Nickname: administratorNickname}, nil
}

func getEvents(all bool) ([]*Event, error) {
	rows, err := db.Query("SELECT id, public_fg FROM events ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var eventID int64
		var isPublic bool
		if err := rows.Scan(&eventID, &isPublic); err != nil {
			return nil, err
		}
		if !all && !isPublic {
			continue
		}
		event, err := getEvent(eventID, -1)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func rankToNum(rank string) int {
	switch rank {
	case "C":
		return 3
	case "B":
		return 2
	case "A":
		return 1
	case "S":
		return 0
	}
	return -1
}

func sheetIDToNum(sheetID int64) int64 {
	if sheetID > 500 {
		return sheetID - 500
	} else if sheetID > 200 {
		return sheetID - 200
	} else if sheetID > 50 {
		return sheetID - 50
	} else {
		return sheetID
	}
}
func sheetNumToID(sheetNum int64, rankNum int) int64 {
	if rankNum == 3 {
		return sheetNum + 500
	} else if rankNum == 2 {
		return sheetNum + 200
	} else if rankNum == 1 {
		return sheetNum + 50
	} else {
		return sheetNum
	}
}

// ランクごとのシート数と料金を返す
func getSheetInfo() ([]int, []int64, error) {
	sheetTotal := []int {0, 0, 0, 0}
	sheetPrice := []int64 {0, 0, 0, 0}
	rows, err := db.Query("SELECT `rank`, COUNT(*), price FROM sheets GROUP BY `rank`")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var rank string
	var total int
	var price int64
	for rows.Next() {
		rows.Scan(&rank, &total, &price)
		sheetTotal[rankToNum(rank)] = total
		sheetPrice[rankToNum(rank)] = price
	}
	return sheetTotal, sheetPrice, nil
}

func getEvent(eventID, loginUserID int64) (*Event, error) {
	var ec *EventCache
	if eventID < int64(len(eventCache)) {
		ec = eventCache[eventID]
	}
	if ec != nil && ec.valid {
		// キャッシュがある場合
		for i, rank := range []string{ "S", "A", "B", "C" } {
			ec.rankMux[i].RLock()
			for _, sheet := range ec.event.Sheets[rank].Detail {
				sheet.Mine = sheet.User == loginUserID
			}
			ec.rankMux[i].RUnlock()
		}
		return ec.event, nil
	}

	// キャッシュのオブジェクト自体がない場合は新規に作成
	if ec == nil && eventID >= int64(len(eventCache)){
		for i := int64(len(eventCache)); i <= eventID; i++ {
			eventCache = append(eventCache, new(EventCache))
		}
	} else if ec == nil{
		eventCache[eventID] = new(EventCache)
	}

	ec = eventCache[eventID]
	ec.mux.RLock()
	defer ec.mux.RUnlock()
	for i := 0; i < 4; i++ {
		ec.rankMux[i].RLock()
		defer ec.rankMux[i].RUnlock()
	}

	var event Event
	event.ID = eventID
	// 指定されたIDのイベントを取得
	if err := db.QueryRow("SELECT title, public_fg, closed_fg, price FROM events WHERE id = ?", eventID).Scan(&event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
		return nil, err
	}
	event.Sheets = map[string]*Sheets{
		"S": &Sheets{},
		"A": &Sheets{},
		"B": &Sheets{},
		"C": &Sheets{},
	}

	// 総席数や価格を先に計算
	for i, rank := range []string{ "S", "A", "B", "C"} {
		sheets := event.Sheets[rank]
		sheets.Total = sheetInfo.total[i]
		sheets.Detail = make([]*Sheet, sheets.Total)
		sheets.Price = event.Price + sheetInfo.price[i]
		event.Total += sheetInfo.total[i]
	}

	// 座席ごとの状況を取得
	rows, err := db.Query("SELECT s.id, s.rank, s.num, r.user_id, r.reserved_at FROM sheets AS s LEFT OUTER JOIN reservations AS r ON s.id = r.sheet_id AND r.event_id = ? AND NOT r.is_canceled", eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var userID sql.NullInt64
	var reservedAt *time.Time
	var remains [4]int
	for rows.Next() {
		var sheet Sheet
		if err := rows.Scan(&sheet.ID, &sheet.Rank, &sheet.Num, &userID, &reservedAt); err != nil {
			return nil, err
		}
		if userID.Valid {
			sheet.User = userID.Int64
			sheet.Mine = userID.Int64 == loginUserID
			sheet.Reserved = true
			sheet.ReservedAtUnix = reservedAt.Unix()
		} else {
			remains[rankToNum(sheet.Rank)]++
		}
		event.Sheets[sheet.Rank].Detail[sheet.Num-1] = &sheet
	}
	for i, rank := range []string{ "S", "A", "B", "C"} {
			event.Remains += remains[i]
			event.Sheets[rank].Remains = remains[i]
	}
	// キャッシュに保存
	ec.event = &event
	ec.valid = true

	return &event, nil
}

func sanitizeEvent(e *Event) *Event {
	sanitized := *e
	sanitized.Price = 0
	sanitized.PublicFg = false
	sanitized.ClosedFg = false
	return &sanitized
}

func fillinUser(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if user, err := getLoginUser(c); err == nil {
			c.Set("user", user)
		}
		return next(c)
	}
}

func fillinAdministrator(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if administrator, err := getLoginAdministrator(c); err == nil {
			c.Set("administrator", administrator)
		}
		return next(c)
	}
}

func validateRank(rank string) bool {
	return rankToNum(rank) != -1
}
func validateNum(rank string, num int64) bool {
	switch rank {
	case "C":
		return 1 <= num && num <= 500
	case "B":
		return 1 <= num && num <= 300
	case "A":
		return 1 <= num && num <= 150
	case "S":
		return 1 <= num && num <= 50
	}
	return false
}

type Renderer struct {
	templates *template.Template
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

var db *sql.DB

type EventCache struct {
	event *Event
	mux sync.RWMutex
	rankMux [4]sync.RWMutex
	valid bool	// eventが有効なキャッシュかどうか
}

type SheetInfo struct {
	total []int
	price []int64
}

type MyArray struct {
	v [500]int64
	length int
}

func (ma *MyArray) At(id int) int64 {
	return ma.v[id]
}

func (ma *MyArray) Add(value int64) {
	ma.v[ma.length] = value
	ma.length++
}

func (ma *MyArray) Delete(id int) {
	ma.v[id] = ma.v[ma.length-1]
	ma.length--
}

// 空いてる座席のリストを保持する構造体
type AvailableSheets struct {
	sheets *MyArray
	mux sync.Mutex
}

// ランダムに1つ空いている座席を取得する
// 空きがない場合は-1を返す
func (as *AvailableSheets) Take() int64 {
	as.mux.Lock()
	defer as.mux.Unlock()
	if as.sheets.length == 0 {
		return -1
	}
	id := rand.Intn(as.sheets.length)
	sheet := as.sheets.At(id)
	as.sheets.Delete(id)
	return sheet
}

// 指定したIDの座席を予約可能にする
func (as *AvailableSheets) Enable(sheet int64) {
	as.mux.Lock()
	defer as.mux.Unlock()
	as.sheets.Add(sheet)
}

// 指定した座席を予約済みにする
func (as *AvailableSheets) Disable(sheet int64) {
	as.mux.Lock()
	defer as.mux.Unlock()
	for i := 0; i < as.sheets.length; i++ {
		if as.sheets.At(i) == sheet {
			as.sheets.Delete(i)
			break
		}
	}
}

func (as *AvailableSheets) Initialize(firstID int64, lastID int64) {
	as.mux.Lock()
	defer as.mux.Unlock()
	as.sheets = new(MyArray)
	for id := firstID; id <= lastID; id++ {
		as.sheets.Add(id)
	}
}

var availableSheets [][4]*AvailableSheets

func initilizeAvailableSheetsEachRank(eventID int64) {
	availableSheets[eventID] = [4]*AvailableSheets{
		new(AvailableSheets),
		new(AvailableSheets),
		new(AvailableSheets),
		new(AvailableSheets),
	}
	var firstID int64 = 1
	for i := 0; i < 4; i++ {
		availableSheets[eventID][i].Initialize(firstID, firstID + int64(sheetInfo.total[i]) - 1)
		firstID += int64(sheetInfo.total[i])
	}
}

// DBの状況を反映する
func setAvailableSheetsFromDB() {
	rows, _ := db.Query("SELECT e.id, s.id, s.rank FROM events AS e LEFT OUTER JOIN (reservations AS r INNER JOIN sheets AS s ON r.sheet_id = s.id) ON e.id = r.event_id AND NOT r.is_canceled")
	defer rows.Close()
	for rows.Next() {
		var eventID int64
		var sheetID int64
		var rank string
		rows.Scan(&eventID, &sheetID, &rank)
		var sheets [4]*AvailableSheets
		if eventID < int64(len(availableSheets)) {
			sheets = availableSheets[eventID]
		} 
		if sheets[0] == nil {
			if eventID < int64(len(availableSheets)) {
				initilizeAvailableSheetsEachRank(eventID)
			} else{
				for i := int64(len(availableSheets)); i <= eventID; i++ {
					availableSheets = append(availableSheets, [4]*AvailableSheets{})
					initilizeAvailableSheetsEachRank(i)
				}
			}
		}
		if sheetID > 0 {
			availableSheets[eventID][rankToNum(rank)].Disable(sheetID)
		}
	}
}

func initializeReport() {
	rows, _ := db.Query("select r.id, r.user_id, r.reserved_at, r.canceled_at, s.rank, s.num, s.price, e.id, e.price from reservations r inner join sheets s on s.id = r.sheet_id inner join events e on e.id = r.event_id")
	defer rows.Close()

	var reservationID int64
	var userID int64
	var reservedAt *time.Time
	var canceledAt *time.Time
	var rank string
	var sheetNum int64
	var sheetPrice int64
	var eventID int64
	var eventPrice int64

	for rows.Next() {
		rows.Scan(&reservationID, &userID, &reservedAt, &canceledAt, &rank, &sheetNum, &sheetPrice, &eventID, &eventPrice)
		report := Report{
			ReservationID: reservationID,
			EventID:       eventID,
			Rank:          rank,
			Num:           sheetNum,
			UserID:        userID,
			SoldAt:        reservedAt,
			Price:         eventPrice + sheetPrice,
		}
		reportRenderer.reports = append(reportRenderer.reports, &report)
		if canceledAt != nil {
			reservationCanceledAt[reservationID] = canceledAt
		}
	}
	sort.Slice(reportRenderer.reports, func(i, j int) bool { return reportRenderer.reports[i].SoldAt.Before(*reportRenderer.reports[j].SoldAt) })
}

func initializeUsers() {
	rows, _ := db.Query("SELECT * FROM users")
	defer rows.Close()
	for rows.Next() {
		var user User
		rows.Scan(&user.ID, &user.Nickname, &user.LoginName, &user.PassHash)
		usersMap[user.LoginName] = &user
	}
}

var eventCache []*EventCache
var sheetInfo SheetInfo
var reportRenderer *ReportRenderer

var usersMap map[string]*User

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4",
		os.Getenv("DB_USER"), os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
		os.Getenv("DB_DATABASE"),
	)

	eventCache = make([]*EventCache, 30)
	availableSheets = make([][4]*AvailableSheets, 30)
	
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}

	// 座席の静的な情報は最初に取得
	sheetInfo.total, sheetInfo.price, _ = getSheetInfo()

	// 予約可能な座席情報を取得する
	setAvailableSheetsFromDB()

	usersMap = make(map[string]*User)
	initializeUsers()

	// レポートの初期化
	reportRenderer = NewReportRenderer()
	reservationCanceledAt = make(map[int64]*time.Time)
	initializeReport()
	

	e := echo.New()
	funcs := template.FuncMap{
		"encode_json": func(v interface{}) string {
			b, _ := json.Marshal(v)
			return string(b)
		},
	}
	e.Renderer = &Renderer{
		templates: template.Must(template.New("").Delims("[[", "]]").Funcs(funcs).ParseGlob("views/*.tmpl")),
	}
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: os.Stderr}))
	e.Static("/", "public")
	e.GET("/", func(c echo.Context) error {
		events, err := getEvents(false)
		if err != nil {
			return err
		}
		for i, v := range events {
			events[i] = sanitizeEvent(v)
		}
		return c.Render(200, "index.tmpl", echo.Map{
			"events": events,
			"user":   c.Get("user"),
			"origin": c.Scheme() + "://" + c.Request().Host,
		})
	}, fillinUser)
	e.GET("/initialize", func(c echo.Context) error {
		cmd := exec.Command("../../db/init.sh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			return nil
		}

		return c.NoContent(204)
	})
	e.POST("/api/users", func(c echo.Context) error {
		var params struct {
			Nickname  string `json:"nickname"`
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		_, found := usersMap[params.LoginName]
		if found {
			return resError(c, "duplicated", 409)
		}

		passHash := sha256.Sum256([]byte(params.Password))
		passHashStr := hex.EncodeToString(passHash[:])
		res, err := tx.Exec("INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, ?, ?)", params.LoginName, passHashStr, params.Nickname)
		if err != nil {
			tx.Rollback()
			return resError(c, "", 0)
		}
		userID, err := res.LastInsertId()
		if err != nil {
			tx.Rollback()
			return resError(c, "", 0)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		usersMap[params.LoginName] = &User{ID: userID, Nickname: params.Nickname, LoginName: params.LoginName, PassHash: passHashStr}

		return c.JSON(201, echo.Map{
			"id":       userID,
			"nickname": params.Nickname,
		})
	})
	e.GET("/api/users/:id", func(c echo.Context) error {
		// ユーザIDとユーザ名を取得し、userという変数に格納
		var user User
		if err := db.QueryRow("SELECT id, nickname FROM users WHERE id = ?", c.Param("id")).Scan(&user.ID, &user.Nickname); err != nil {
			return err
		}

		loginUser, err := getLoginUser(c)
		if err != nil {
			return err
		}
		if user.ID != loginUser.ID {
			return resError(c, "forbidden", 403)
		}
		// 先に、直近に予約・キャンセルした予約一覧を取得
		rows, err := db.Query("SELECT e.* FROM events AS e INNER JOIN reservations AS r ON r.user_id = ? AND e.id = r.event_id GROUP BY event_id ORDER BY MAX(IFNULL(canceled_at, reserved_at)) DESC LIMIT 5", user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var recentEvents []*Event
		var eventMap map[int64]*Event = make(map[int64]*Event)
		for rows.Next() {
			var event Event
			if err := rows.Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
				return err
			}
			recentEvents = append(recentEvents, &event)
			eventMap[event.ID] = &event
		}

		// 各シートごとの総数を計算
		for _, v := range recentEvents {
			v.Sheets = map[string]*Sheets{
				"S": &Sheets{},
				"A": &Sheets{},
				"B": &Sheets{},
				"C": &Sheets{},
			}
			for i, rank := range []string{"S", "A", "B", "C"} {
				total := sheetInfo.total[i]
				v.Sheets[rank].Total = total
				v.Sheets[rank].Remains = total	// あとで引いていくので初期値は総数とする
				v.Sheets[rank].Price = sheetInfo.price[i] + v.Price
				v.Total += total
			}
			v.Remains = v.Total
		}
		// 予約済みシートの取得
		rows, err = db.Query("SELECT event_id, rank, COUNT(*) FROM reservations as r INNER JOIN sheets as s ON NOT r.is_canceled AND r.sheet_id = s.id GROUP BY event_id, s.rank")
		if err != nil {
			return err
		}
		defer rows.Close()

		var eventID int64
		var rank string
		var reservedNum int
		// 予約済みの分を引いていく
		for rows.Next() {
			rows.Scan(&eventID, &rank, &reservedNum)
			if eventMap[eventID] == nil {
				continue
			}
			eventMap[eventID].Remains -= reservedNum
			eventMap[eventID].Sheets[rank].Remains -= reservedNum
		}
		// recentEvents 取得完了

		// キャンセル日時、または予約日時が新しい順に最大五件の予約情報を取得する
		rows, err = db.Query("SELECT r.id, r.event_id, r.sheet_id, r.user_id, r.reserved_at, r.canceled_at, s.rank, s.num FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id WHERE r.user_id = ? ORDER BY IFNULL(r.canceled_at, r.reserved_at) DESC LIMIT 5", user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		var recentReservations []Reservation
		recentReservations = make([]Reservation, 5)
		
		rowNum := 0
		for rows.Next() {
			var rank string
			var sheetNum int64
			reservation := &recentReservations[rowNum]
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &rank, &sheetNum); err != nil {
				return err
			}
			event := eventMap[reservation.EventID]
			reservation.Event = &Event{}
			reservation.Event.ID = event.ID
			reservation.Event.Title = event.Title
			reservation.Event.PublicFg = event.PublicFg
			reservation.Event.ClosedFg = event.ClosedFg
			reservation.Event.Price = event.Price
			reservation.SheetRank = rank
			reservation.SheetNum = sheetNum
			reservation.Price = event.Sheets[rank].Price
			reservation.ReservedAtUnix = reservation.ReservedAt.Unix()
			if reservation.CanceledAt != nil {
				reservation.CanceledAtUnix = reservation.CanceledAt.Unix()
			}
			rowNum++
		}
		if rowNum == 0 {
			recentReservations = make([]Reservation, 0)
		}
		// recentReservations 取得完了
		
		// 総額の計算
		var totalPrice int
		if err := db.QueryRow("SELECT IFNULL(SUM(e.price + s.price), 0) FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.user_id = ? AND NOT r.is_canceled", user.ID).Scan(&totalPrice); err != nil {
			return err
		}
		return c.JSON(200, echo.Map{
			"id":                  user.ID,
			"nickname":            user.Nickname,
			"recent_reservations": recentReservations,
			"total_price":         totalPrice,
			"recent_events":       recentEvents,
		})
	}, loginRequired)
	e.POST("/api/actions/login", func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		user, ok := usersMap[params.LoginName]
		if !ok {
			return resError(c, "authentication_failed", 401)
		}
		/*
		var passHash string
		if err := db.QueryRow("SELECT SHA2(?, 256)", params.Password).Scan(&passHash); err != nil {
			return err
		}
		if user.PassHash != passHash {
			return resError(c, "authentication_failed", 401)
		}*/
		passHash := sha256.Sum256([]byte(params.Password))
		if user.PassHash != hex.EncodeToString(passHash[:]) {
			return resError(c, "authentication_failed", 401)
		}

		sessSetUserID(c, user.ID, user.Nickname)
		user, err = getLoginUser(c)
		if err != nil {
			return err
		}
		return c.JSON(200, user)
	})
	e.POST("/api/actions/logout", func(c echo.Context) error {
		sessDeleteUserID(c)
		return c.NoContent(204)
	}, loginRequired)
	e.GET("/api/events", func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		for i, v := range events {
			events[i] = sanitizeEvent(v)
		}
		return c.JSON(200, events)
	})
	e.GET("/api/events/:id", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		loginUserID := int64(-1)
		if user, err := getLoginUser(c); err == nil {
			loginUserID = user.ID
		}

		event, err := getEvent(eventID, loginUserID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		} else if !event.PublicFg {
			return resError(c, "not_found", 404)
		}
		return c.JSON(200, sanitizeEvent(event))
	})
	e.POST("/api/events/:id/actions/reserve", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		var params struct {
			Rank string `json:"sheet_rank"`
		}
		c.Bind(&params)

		if !validateRank(params.Rank) {
			return resError(c, "invalid_rank", 400)
		}

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		rankNum := rankToNum(params.Rank)
		ec := eventCache[eventID]
		if ec == nil || ec.event == nil {
			return resError(c, "invalid_event", 404)
		}
		if !ec.event.PublicFg {
			return resError(c, "invalid_event", 404)
		}

		// ランダムに1席選択
		selectID := availableSheets[eventID][rankNum].Take()

		reservedAt := time.Now().UTC()
		res, err := db.Exec("INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at) VALUES (?, ?, ?, ?)", eventID, selectID, user.ID, reservedAt.Format("2006-01-02 15:04:05.000000"))
		if err != nil {
			return err
		}
		reservationID, err := res.LastInsertId()
		if err != nil {
			return err
		}
		go func() {
			report := Report{
				ReservationID: reservationID,
				EventID:       eventID,
				Rank:          params.Rank,
				Num:           sheetIDToNum(selectID),
				UserID:        user.ID,
				SoldAt:        &reservedAt,
				Price:         ec.event.Price + sheetInfo.price[rankNum],
			}
			reportRenderer.reportChan <- &report
		}()

		ec.rankMux[rankNum].Lock()
		for _, s := range ec.event.Sheets[params.Rank].Detail {
			if s.ID == selectID {
				s.User = user.ID
				s.Reserved = true
				s.ReservedAt = &reservedAt
				s.ReservedAtUnix = reservedAt.Unix()
				break
			}
		}
		ec.event.Sheets[params.Rank].Remains--
		ec.rankMux[rankNum].Unlock()

		ec.mux.Lock()
		ec.event.Remains--
		ec.mux.Unlock()
		
		return c.JSON(202, echo.Map{
			"id":         reservationID,
			"sheet_rank": params.Rank,
			"sheet_num":  sheetIDToNum(selectID),
		})
	}, loginRequired)
	e.DELETE("/api/events/:id/sheets/:rank/:num/reservation", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		rank := c.Param("rank")
		num, err := strconv.ParseInt(c.Param("num"), 10, 64)
		if err != nil {
			return resError(c, "invalid_sheet", 404)
		}

		if !validateRank(rank) {
			return resError(c, "invalid_rank", 404)
		}

		if !validateNum(rank, num) {
			return resError(c, "invalid_sheet", 404)
		}

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		rankNum := rankToNum(rank)
		ec := eventCache[eventID]
		if ec != nil && ec.event != nil {
			if !ec.event.PublicFg {
				return resError(c, "invalid_event", 404)
			}
		} else {
			return resError(c, "invalid_event", 404)
		}

		sheetID := sheetNumToID(num, rankNum)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		var reservationID int64
		var userID int64
		if err := tx.QueryRow("SELECT id, user_id FROM reservations WHERE event_id = ? AND sheet_id = ? AND NOT is_canceled FOR UPDATE", eventID, sheetID).Scan(&reservationID, &userID); err != nil {
			tx.Rollback()
			if err == sql.ErrNoRows {
				return resError(c, "not_reserved", 400)
			}
			return err
		}
		if userID != user.ID {
			tx.Rollback()
			return resError(c, "not_permitted", 403)
		}

		canceledAt := time.Now().UTC()
		if _, err := tx.Exec("UPDATE reservations SET canceled_at = ?, is_canceled = TRUE WHERE id = ?", canceledAt.Format("2006-01-02 15:04:05.000000"), reservationID); err != nil {
			tx.Rollback()
			return err
		}
		reservationCanceledAt[reservationID] = &canceledAt

		if err := tx.Commit(); err != nil {
			return err
		}
		// 予約可能にする
		availableSheets[eventID][rankNum].Enable(sheetID)

		ec.rankMux[rankNum].Lock()
		for _, s := range ec.event.Sheets[rank].Detail {
			if s.ID == sheetID {
				s.User = -1
				s.Reserved = false
				s.ReservedAt = nil
				s.ReservedAtUnix = 0
				break
			}
		}
		ec.event.Sheets[rank].Remains++
		ec.rankMux[rankNum].Unlock()

		ec.mux.Lock()
		ec.event.Remains++
		ec.mux.Unlock()

		return c.NoContent(204)
	}, loginRequired)
	e.GET("/admin/", func(c echo.Context) error {
		var events []*Event
		administrator := c.Get("administrator")
		if administrator != nil {
			var err error
			if events, err = getEvents(true); err != nil {
				return err
			}
		}
		return c.Render(200, "admin.tmpl", echo.Map{
			"events":        events,
			"administrator": administrator,
			"origin":        c.Scheme() + "://" + c.Request().Host,
		})
	}, fillinAdministrator)
	e.POST("/admin/api/actions/login", func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		administrator := new(Administrator)
		if err := db.QueryRow("SELECT * FROM administrators WHERE login_name = ?", params.LoginName).Scan(&administrator.ID, &administrator.Nickname, &administrator.LoginName, &administrator.PassHash); err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "authentication_failed", 401)
			}
			return err
		}
		/*
		var passHash string
		if err := db.QueryRow("SELECT SHA2(?, 256)", params.Password).Scan(&passHash); err != nil {
			return err
		}
		if administrator.PassHash != passHash {
			return resError(c, "authentication_failed", 401)
		}*/
		passHash := sha256.Sum256([]byte(params.Password))
		if administrator.PassHash != hex.EncodeToString(passHash[:]) {
			return resError(c, "authentication_failed", 401)
		}

		sessSetAdministratorID(c, administrator.ID, administrator.Nickname)
		administrator, err = getLoginAdministrator(c)
		if err != nil {
			return err
		}
		return c.JSON(200, administrator)
	})
	e.POST("/admin/api/actions/logout", func(c echo.Context) error {
		sessDeleteAdministratorID(c)
		return c.NoContent(204)
	}, adminLoginRequired)
	e.GET("/admin/api/events", func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		return c.JSON(200, events)
	}, adminLoginRequired)
	e.POST("/admin/api/events", func(c echo.Context) error {
		var params struct {
			Title  string `json:"title"`
			Public bool   `json:"public"`
			Price  int    `json:"price"`
		}
		c.Bind(&params)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		res, err := tx.Exec("INSERT INTO events (title, public_fg, closed_fg, price) VALUES (?, ?, 0, ?)", params.Title, params.Public, params.Price)
		if err != nil {
			tx.Rollback()
			return err
		}
		eventID, err := res.LastInsertId()
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if eventID >= int64(len(eventCache)) {
			for i := int64(len(eventCache)); i <= eventID; i++ {
				eventCache = append(eventCache, new(EventCache))
			}
		} else {
			eventCache[eventID] = new(EventCache)
		}
		initilizeAvailableSheetsEachRank(eventID)

		event, err := getEvent(eventID, -1)
		if err != nil {
			return err
		}
		return c.JSON(200, event)
	}, adminLoginRequired)
	e.GET("/admin/api/events/:id", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		event, err := getEvent(eventID, -1)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}
		return c.JSON(200, event)
	}, adminLoginRequired)
	e.POST("/admin/api/events/:id/actions/edit", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		var params struct {
			Public bool `json:"public"`
			Closed bool `json:"closed"`
		}
		c.Bind(&params)

		if params.Closed {
			params.Public = false
		}

		event, err := getEvent(eventID, -1)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}

		if event.ClosedFg {
			return resError(c, "cannot_edit_closed_event", 400)
		} else if event.PublicFg && params.Closed {
			return resError(c, "cannot_close_public_event", 400)
		}

		ec := eventCache[eventID]
		if ec != nil && ec.event != nil {
			ec.mux.Lock()
			defer ec.mux.Unlock()
		}
		
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?", params.Public, params.Closed, event.ID); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		event.PublicFg = params.Public
		event.ClosedFg = params.Closed

		c.JSON(200, event)
		return nil
	}, adminLoginRequired)
	e.GET("/admin/api/reports/events/:id/sales", func(c echo.Context) error {
		
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		/*
		rows, err := db.Query("SELECT r.id, r.user_id, r.reserved_at, r.canceled_at, s.rank, s.num, s.price, e.price FROM (reservations AS r INNER JOIN events AS e ON r.event_id = e.id AND e.id = ?) INNER JOIN sheets AS s ON r.sheet_id = s.id", eventID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var reports []*Report
		var reservationID int64
		var userID int64
		var reservedAt *time.Time
		var canceledAt *time.Time
		var rank string
		var sheetNum int64
		var sheetPrice int64
		var eventPrice int64

		for rows.Next() {
			if err := rows.Scan(&reservationID, &userID, &reservedAt, &canceledAt, &rank, &sheetNum, &sheetPrice, &eventPrice); err != nil {
				return err
			}
			report := Report{
				ReservationID: reservationID,
				EventID:       eventID,
				Rank:          rank,
				Num:           sheetNum,
				UserID:        userID,
				SoldAt:        reservedAt,
				Price:         eventPrice + sheetPrice,
			}
			if canceledAt != nil {
				report.CanceledAt = canceledAt
			}
			reports = append(reports, &report)
		}
		return renderReportCSV(c, reports)
		*/
		reportRenderer.inChan <- &ReportRequest{context: c, eventID: eventID}
		return <- reportRenderer.outChan
	}, adminLoginRequired)
	e.GET("/admin/api/reports/sales", func(c echo.Context) error {
		/*
		rows, err := db.Query("select r.id, r.user_id, r.reserved_at, r.canceled_at, s.rank, s.num, s.price, e.id, e.price from reservations r inner join sheets s on s.id = r.sheet_id inner join events e on e.id = r.event_id")
		if err != nil {
			return err
		}
		defer rows.Close()

		var reports []*Report
		var reservationID int64
		var userID int64
		var reservedAt *time.Time
		var canceledAt *time.Time
		var rank string
		var sheetNum int64
		var sheetPrice int64
		var eventID int64
		var eventPrice int64

		for rows.Next() {
			if err := rows.Scan(&reservationID, &userID, &reservedAt, &canceledAt, &rank, &sheetNum, &sheetPrice, &eventID, &eventPrice); err != nil {
				return err
			}
			report := Report{
				ReservationID: reservationID,
				EventID:       eventID,
				Rank:          rank,
				Num:           sheetNum,
				UserID:        userID,
				SoldAt:        reservedAt,
				CanceledAt:    canceledAt,
				Price:         eventPrice + sheetPrice,
			}
			reports = append(reports, &report)
		}
		return renderReportCSV(c, reports)
		*/
		reportRenderer.inChan <- &ReportRequest{context: c, eventID: -1}
		return <- reportRenderer.outChan
	}, adminLoginRequired)

	e.Start(":8080")
}

type Report struct {
	ReservationID int64
	EventID       int64
	Rank          string
	Num           int64
	UserID        int64
	SoldAt        *time.Time
	CanceledAt    *time.Time
	Price         int64
}

func renderReportCSV(c echo.Context, reports []*Report, eventID int64) error {
	//sort.Slice(reports, func(i, j int) bool { return reports[i].SoldAt.Before(*reports[j].SoldAt) })
	body := bytes.NewBufferString("reservation_id,event_id,rank,num,price,user_id,sold_at,canceled_at\n")
	for _, v := range reports {
		if eventID != -1 && v.EventID != eventID {
			continue
		}
		var canceledAt string
		if t, found := reservationCanceledAt[v.ReservationID]; found {
			canceledAt = t.Format("2006-01-02T15:04:05.000000Z")
		}
		body.WriteString(fmt.Sprintf("%d,%d,%s,%d,%d,%d,%s,%s\n",
			v.ReservationID, v.EventID, v.Rank, v.Num, v.Price, v.UserID, v.SoldAt.Format("2006-01-02T15:04:05.000000Z"), canceledAt))
	}

	c.Response().Header().Set("Content-Type", `text/csv; charset=UTF-8`)
	c.Response().Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
	_, err := io.Copy(c.Response(), body)
	return err
}

func resError(c echo.Context, e string, status int) error {
	if e == "" {
		e = "unknown"
	}
	if status < 100 {
		status = 500
	}
	return c.JSON(status, map[string]string{"error": e})
}

type ReportRenderer struct {
	inChan chan *ReportRequest
	outChan chan error
	reportChan chan *Report
	lastTime *time.Time
	reports []*Report
	reportsByEvent[][]*Report
}

type ReportRequest struct {
	context echo.Context
	eventID int64
}

var reservationCanceledAt map[int64]*time.Time

func NewReportRenderer() *ReportRenderer {
	rr := new(ReportRenderer)
	rr.inChan = make(chan *ReportRequest)
	rr.outChan = make(chan error)
	rr.reportChan = make(chan *Report)
	rr.reports = make([]*Report, 0, 200000)
	rr.lastTime = new(time.Time)
	go func() {
		for true {
			select {
			case req := <- rr.inChan:
				rr.outChan <- renderReportCSV(req.context, rr.reports, req.eventID)
			case r := <- rr.reportChan:
				var flag bool
				for i := len(rr.reports)-1; i >= 0; i-- {
					if r.SoldAt.After(*rr.reports[i].SoldAt) {
						rr.reports = append(rr.reports[:i+1], append([]*Report{r}, rr.reports[i+1:]...)...)
						flag = true
						break
					}
				}
				if !flag {
					rr.reports = append([]*Report{r}, rr.reports...)
				}
			}
		}
	}()
	return rr
}