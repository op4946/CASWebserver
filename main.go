//TODO: Check all unusual errors to make sure the are handled properly, especially the 500 ones
//	:	Respect visibility options in search and public pages
//	:	complete implementation for popularity rankings and make the home page less empty
//	:	work on preventing popularity rigging
package main

import (
	"fmt"
	"time"
	"log"
	"io/ioutil"
	"net/http"// Built in http webserver
	"html/template"
	"database/sql"

	"github.com/julienschmidt/httprouter"// Third party router to provide extra features
	_ "github.com/mattn/go-sqlite3"//		SQLite driver
)

var sqldb *sql.DB
var sessiondb *sql.DB
var domain string

func GetRoot(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.Printf("%s visited home page! (%s)\n", r.RemoteAddr, r.UserAgent())

	cookie := UUIDCookie(r)

	var templateData = struct {
		URLs []string
		Users []string
		LoggedIn bool
	}{ }

	if cookie == nil {
		templateData.LoggedIn = false
	} else {
		username := UserFromUUID(cookie.Value)
		if username == "" {
			templateData.LoggedIn = false
		} else {
			templateData.LoggedIn = true
		}
	}

	statement, _ := sqldb.Prepare("SELECT url from urls WHERE visibility=0 ORDER BY popularity DESC LIMIT 7")
	rows, err := statement.Query();

	var tmpurl string
	for rows.Next() {
		rows.Scan(&tmpurl)
		templateData.URLs = append(templateData.URLs, tmpurl)
	}

	statement, _ = sqldb.Prepare("SELECT username from users ORDER BY popularity DESC LIMIT 7")
	rows, err = statement.Query();

	var tmpuser string
	for rows.Next() {
		rows.Scan(&tmpuser)
		templateData.Users = append(templateData.Users, tmpuser)
	}

	err = templates.ExecuteTemplate(w, "home.html", templateData)
	if err != nil {
		fmt.Println("Err serving / : ", err)
		return
	}
}

func PostSaveURL(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	cookie := UUIDCookie(r)

	if cookie == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	username := UserFromUUID(cookie.Value)

	if username == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	r.ParseForm()

//	check if valid URL
	if r.PostForm["URL"][0] == "" {
		fmt.Fprint(w, "Invalid form!")
		return
	}

	statement, err := sqldb.Prepare("INSERT INTO urls (url, uploader, visibility, popularity) VALUES (?, ?, ?, 0)")

	if err != nil {
		fmt.Println("Error preparing statement while serving POST /saveurl : ", err)
		w.WriteHeader(500)
		return
	}

	var visibility int

//	Public: 0
//	Private: 1
//	More options (unlisted) may be added later
	switch v := r.PostForm["private"][0]
	{
		case v == "0":
			visibility = 0
		case v == "1":
			visibility = 1
		default:
			fmt.Fprint(w, "Invalid form!")
			return
	}

	_, err = statement.Exec(r.PostForm["URL"][0], username, visibility)

	if err != nil {
		fmt.Println("Error adding url to db while serving POST /saveurl : ", err)
		w.WriteHeader(500)
		return
	}

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func UUIDCookie(r *http.Request) *http.Cookie {
	cookie, err := r.Cookie("User")
	
	if err != nil {
		return nil
	}

	return cookie
}

func GetViewURLs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	cookie := UUIDCookie(r)
	var authUsername string

//	TODO: Implement tags properly
	var templateData = struct {
		URLs []string
		Tags []string
		LoggedIn bool
		Username string
	}{ }
	
	if cookie == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	} else {
		authUsername = UserFromUUID(cookie.Value)
		fmt.Println(authUsername);

		if authUsername != "" {
			templateData.LoggedIn = true
			templateData.Username = authUsername
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	statement, _ := sqldb.Prepare("SELECT url, tags FROM urls WHERE uploader=?")

	rows, err := statement.Query(authUsername)
	
	if err != nil {
		fmt.Printf("Error querying db for urls from user (%s) while serving GET /account : %v\n", authUsername, err)
		fmt.Fprint(w, "Error getting your urls")
		return
	}

	defer rows.Close();

	var tmpurl string
	var tmptag string

	for rows.Next() {
		rows.Scan(&tmpurl, &tmptag)
		templateData.URLs = append(templateData.URLs, tmpurl)
		templateData.Tags = append(templateData.Tags, tmptag)
	}

	err = templates.ExecuteTemplate(w, "viewurls.html", templateData)

	if err != nil {
		fmt.Println("Error executing template while serving GET /account : ", err)
		fmt.Fprint(w, "An error occured")
	}
}

func RedirectWrapper(path string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		http.ServeFile(w, r, path)
	}
}

func GetLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	http.ServeFile(w, r, "static/login")
}

func PostLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	r.ParseForm();

	if (r.PostForm["username"][0] == "" || r.PostForm["password"][0] == "") {
		http.ServeFile(w, r, "static/loginerror")
		return
	}

	statement, _ := sqldb.Prepare("SELECT password FROM users WHERE username=?")

//	Make sure the response for valid username and password is the same (bad actors cannot check if a user exist without right password)
//	The response only needs to be changed here to update both
	loginErrHandler := func() {
		log.Printf("Failed login : creds (%s, %s)", r.PostForm["username"][0], r.PostForm["password"][0])
		http.ServeFile(w, r, "static/loginerror")
	}

	var passwordHash string
	err := statement.QueryRow(r.PostForm["username"][0]).Scan(&passwordHash)
//	check for valid username
	if err != nil {
		loginErrHandler()
		return
	}


	err = CheckPassword(passwordHash, r.PostForm["password"][0])
//	check for valid password
	if err != nil {
	loginErrHandler()
		return
	}

	str, err := GenerateRandomStringURLSafe(128)
	if err != nil {
		fmt.Println("Err generating secure random string while serving POST /login : ", err)
		w.WriteHeader(500)
		return
	}

	statement, _ = sessiondb.Prepare("INSERT INTO sessions (UUID, username, expiryTime) VALUES (?,?,?)")
	_, err = statement.Exec(str, r.PostForm["username"][0], time.Now().Add(time.Hour * 3).Unix())

	if err != nil {
		fmt.Println("Err adding session data to db while serving POST /login : ", err)
		w.WriteHeader(500)
		return
	}

	cookie := &http.Cookie{Name:"User", Value:str, Path:"/", Domain:domain, Expires: time.Now().Add(1 * time.Hour)}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func PostLogout(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	r.ParseForm()

	cookie, _ := r.Cookie("User")

	if cookie != nil {
		statement, _ := sessiondb.Prepare("DELETE FROM sessions WHERE UUID=?")
		_, err := statement.Exec(cookie.Value)
		if err != nil {
			fmt.Println("Error deleting user from sessiondb while serving POST /logout : ", err)
		}
	} else {
	//	If no valid cookie return 422
		http.Error(w, http.StatusText(422), 422)
		return
	}

//	Delete the user's old cookie
	cookie = &http.Cookie{Name:"User", MaxAge:-1}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetNewUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	http.ServeFile(w, r, "static/newuser.html")
}

func PostNewUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	r.ParseForm()

	username := r.PostForm["username"][0]

	if username == "" || r.PostForm["password"][0] == "" {
		fmt.Fprint(w, "No empty fields allowed")
		return
	}

	for _, letter := range username {
		if letter == ' ' {
			fmt.Fprint(w, "No spaces allowed in username")
			return
		}
	}

	statement, _ := sqldb.Prepare("INSERT INTO users (username,password,creationTime, popularity) VALUES (?,?,dateTime())")

	passwordHash, err := HashPassword(r.PostForm["password"][0])

	if err != nil {
		fmt.Println("Error hashing password while serving POST /newuser : ", err)
		w.WriteHeader(500)
		return
	}

	_, err = statement.Exec(username, passwordHash)

	if err != nil {
		fmt.Println("Error adding new user to db while serving POST /newuser : ", err)
		fmt.Fprint(w, "User name already taken!")
		return
	}

	str, err := GenerateRandomStringURLSafe(128)
	if err != nil {
		fmt.Println("Err creating UUID while serving POST /newuser : ", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	statement, _ = sessiondb.Prepare("INSERT INTO sessions (UUID, username, expiryTime) VALUES (?,?,?)")
	_, err = statement.Exec(str, r.PostForm["username"][0], time.Now().Add(time.Hour * 3).Unix())

	if err != nil {
		fmt.Println("Err adding newuser info to session db while serving /newuser : ", err)
		fmt.Fprint(w, "Bad username!")
		return
	}

	cookie := &http.Cookie{Name:"User", Value:str, Path:"/", Expires: time.Now().Add(1 * time.Hour), MaxAge: 86400}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/account", http.StatusFound)
}

func GetSearch(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	query := r.URL.Query().Get("q")

	cookie := UUIDCookie(r)

	var username string

	if cookie != nil {
		username = UserFromUUID(cookie.Value)

		if username == "" {
			fmt.Fprint(w, "Must be logged in to search users!")
			return
		}

	} else {
		fmt.Fprint(w, "Must be logged in to search users!")
		return
	}

//	this search will return every username if the query is blank -avoid that-
	if query == "" {
		fmt.Fprint(w, "No blank queries");
		return;
	}

	var templateData = struct {
		LoggedIn	bool
		URLs		[]string
		Uploader	[]string
		Users		[]string
	}{
		LoggedIn: true,
	}

//	Do loose query for users in the db
	statement, err := sqldb.Prepare("SELECT username FROM users WHERE username LIKE '%'||?||'%' LIMIT 10")

	rows, err := statement.Query(query)

	if err != nil {
		fmt.Printf("Error querying db for user while serving GET /search : %s with query %s\n", err, query);
		w.WriteHeader(500);

		return;
	}

	var user string
	for rows.Next() {
		rows.Scan(&user)
		templateData.Users = append(templateData.Users, user)
	}

	rows.Close()

	statement, err = sqldb.Prepare("SELECT url, uploader FROM urls WHERE (url LIKE '%'||?||'%' OR uploader=?) AND visibility=0 LIMIT 10")

	rows, err = statement.Query(query, query)

	if err != nil {
		fmt.Printf("Error querying db for user while serving GET /search : %s with query %s\n", err, query);
		w.WriteHeader(500);

		return;
	}

	var url, uploader string

	for rows.Next() {
		rows.Scan(&url, &uploader)
		templateData.URLs = append(templateData.URLs, url)
		templateData.Uploader = append(templateData.Uploader, uploader)
	}

	err = templates.ExecuteTemplate(w, "search.html", templateData)

	if err != nil {
		fmt.Println("Error executing template 'search.html' while serving GET /search : ", err)
	}

	rows.Close()
}

func GetUserPage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	cookie := UUIDCookie(r)

	var username string

	if cookie != nil {
		username = UserFromUUID(cookie.Value)

		if username == "" {
			fmt.Fprint(w, "Must be logged in to view users!")
			return
		}
	} else {
		fmt.Fprint(w, "Must be logged in to view users!")
		return
	}

	/*
	statement, _ := sqldb.Prepare("SELECT True FROM users WHERE username=?")

	var exist bool
	err := statement.QueryRow(ps.ByName("user")).Scan(&exist)
	
	if err != nil {
		if err == sql.ErrNoRows {
			NotFound(w, r)
			return
		}

		fmt.Printf("Error querying db for user while serving GET /user/%s : %v\n", ps.ByName("user"), err)
		w.WriteHeader(500)
		return
	}
*/

	statement, _ := sqldb.Prepare("UPDATE users SET popularity = popularity + 1 WHERE username=?")
	res, err := statement.Exec(ps.ByName("user"))

	if err != nil {
		fmt.Printf("Error updating popularity while serving GET /users/%s : %s\n", ps.ByName("user"), err)
		return
	}

	rowsAffected , _ := res.RowsAffected()

	if rowsAffected == 0 {
			NotFound(w, r)
			return
	}

	statement, _ = sqldb.Prepare("SELECT url FROM urls WHERE uploader=? AND visibility=0")

	rows, err := statement.Query(ps.ByName("user"))
	
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(404)
		} else {
			fmt.Printf("Error querying db for urls from user (%s) while serving GET /users/%s : %v\n", ps.ByName("user"), ps.ByName("user"), err)
			w.WriteHeader(500)
		}

		return
	}

	var templateData = struct {
		URLs []string
		Username string
		LoggedIn bool
	}{ LoggedIn: true }

	templateData.Username = ps.ByName("user")

	var tmpurl string

	for rows.Next() {
		rows.Scan(&tmpurl)
		templateData.URLs = append(templateData.URLs, tmpurl)
	}

	rows.Close();

	err = templates.ExecuteTemplate(w, "userPage.html", templateData)

	if err != nil {
		fmt.Printf("Error executing template while serving POST /users/%s : %v", ps.ByName("user"), err)
	}

}

func Favicon(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	http.ServeFile(w, r, "favicon.ico")
}

func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(404)
//	Must use this in order to actually send a 404 back, ServeFile will call WriteHeader on its own
	data, _ := ioutil.ReadFile("static/notfound.html")
	fmt.Fprint(w, string(data))
}

// critical authentication function, be careful if modifying it
func UserFromUUID(UUID string) string {
	statement, _ := sessiondb.Prepare("SELECT username FROM sessions WHERE UUID=?")
	var username string

	err := statement.QueryRow(UUID).Scan(&username)

	if err != nil {
		return ""
	}

	return username
}

var templates *template.Template

func main() {
	router := httprouter.New()// Init httprouter

	router.HandleMethodNotAllowed = false
	router.HandleOPTIONS = false
	router.NotFound = http.HandlerFunc(NotFound)
	fmt.Printf("%v\n", router)

	var err error
	sqldb, err = sql.Open("sqlite3", "database.db")//	Open our main database

	if err != nil {
		fmt.Println("Error opening sqldatabase: ", err)
		return
	}

	sessiondb, err = sql.Open("sqlite3", ":memory:")

	if err != nil {
		fmt.Println("Error starting in-memory sqlite session db : ", err)
		return
	}

	_, err = sessiondb.Exec("CREATE TABLE sessions (UUID string not null, username string, expiryTime INTEGER);")

	if err != nil {
		fmt.Println("Err creating table for session db : ", err)
		return
	}

	templates, err = template.ParseGlob("templates/*")

	if err != nil {
		fmt.Println("Error parsing templates: ", err)
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		target := "https://" + r.Host + r.URL.Path
		if(len(r.URL.RawQuery) > 0) {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})

	go http.ListenAndServe(":80", nil)

	router.GET("/",				GetRoot)
	router.GET("/favicon.ico",	Favicon)
	router.GET("/saveurl",		RedirectWrapper("static/saveurl"))
	router.POST("/saveurl", 	PostSaveURL)
	router.GET("/account",		GetViewURLs)
	router.GET("/login",		GetLogin)
	router.POST("/login",		PostLogin)
	router.POST("/logout",		PostLogout)
	router.GET("/newuser",		GetNewUser)
	router.POST("/newuser",		PostNewUser)
	router.GET("/search",		GetSearch)
	router.GET("/users/:user",	GetUserPage)
	router.ServeFiles("/pages/*filepath", http.Dir("static/"))

	domain = "seganeptune.com"
	fmt.Println("Server started at ", domain)
	fmt.Println(http.ListenAndServeTLS(":443", "tls/cert.pem", "tls/privkey.pem", router))
	//fmt.Println(http.ListenAndServe(":8080", router))
}
