//TODO: Check all unusual errors to make sure the are handled properly, especially the 500 ones
package main

import (
	"fmt"
	"time"
	"net/http"// Built in http webserver
	"html/template"
	"database/sql"

	"github.com/julienschmidt/httprouter"// Third party router to provide extra features
	_ "github.com/mattn/go-sqlite3"//		SQLite driver
)

var sqldb *sql.DB
var sessiondb *sql.DB

func GetRoot(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fmt.Printf("%s visited the home page!\n", r.RemoteAddr)
	http.ServeFile(w, r, "templates/home.html")

/*	Will need this later
	err := templates.ExecuteTemplate(w, "home.html", nil)
	if err != nil {
		fmt.Println("Err serving / : ", err)
		return
	}
*/
}

func PostSaveURL(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	cookie := UUIDCookie(r)

	if cookie == nil {
		http.Redirect(w, r, "/pages/login", http.StatusSeeOther)
		return
	}

	username := UserFromUUID(cookie.Value)

	if username == "" {
		http.Redirect(w, r, "/pages/login", http.StatusSeeOther)
		return
	}

	r.ParseForm()

	statement, err := sqldb.Prepare("INSERT INTO urls (url, uploader) VALUES (?, ?)")

	if err != nil {
		fmt.Println("Error preparing statement while serving POST /saveurl : ", err)
		w.WriteHeader(500)
		return
	}

	_, err = statement.Exec(r.PostForm["URL"][0], username)

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
	
	if cookie == nil {
		http.Redirect(w, r, "/pages/login", http.StatusSeeOther)
		return
	}
	
	var templateData = struct {
		URLs []string
	}{ }

	username := UserFromUUID(cookie.Value)

	if username == "" {
		fmt.Println("No valid username found while serving GET /account : ")
		fmt.Fprint(w, "Error with session token, try relogging in")
		return
	}

	statement, _ := sqldb.Prepare("SELECT url FROM urls WHERE uploader=?")

	rows, err := statement.Query(username)
	
	if err != nil {
		fmt.Printf("Error querying db for urls from user (%s) while serving GET /account : %v\n", username, err)
		fmt.Fprint(w, "Error getting your urls")
		return
	}

	defer rows.Close();

	var tmpurl string

	for rows.Next() {
		rows.Scan(&tmpurl)
		templateData.URLs = append(templateData.URLs, tmpurl)
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

	var passwordHash string
	err := statement.QueryRow(r.PostForm["username"][0]).Scan(&passwordHash)
	if err != nil {
		fmt.Println("Error getting pass from db while serving POST /login : ", err)
		http.ServeFile(w, r, "static/loginerror")
		return
	}

	err = CheckPassword(passwordHash, r.PostForm["password"][0])
	if err != nil {
		http.ServeFile(w, r, "static/loginerror")
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

	//cookie := &http.Cookie{Name:"User", Value:str, Path:"/", Domain:"seganeptune.com", Expires: time.Now().Add(1 * time.Hour)}
	cookie := &http.Cookie{Name:"User", Value:str, Path:"/", Expires: time.Now().Add(1 * time.Hour)}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func GetNewUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	http.ServeFile(w, r, "static/newuser.html")
}

func PostNewUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	r.ParseForm()

	username := r.PostForm["username"][0]
	for _, letter := range username {
		if letter == ' ' {
			fmt.Fprint(w, "No spaces allowed in username")
			return
		}
	}

	statement, _ := sqldb.Prepare("INSERT INTO users (username,password,creationTime) VALUES (?,?,dateTime())")

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
//	TODO: Maybe we could just POST redirect to the login page

	str, err := GenerateRandomStringURLSafe(128)
	if err != nil {
		fmt.Println("Err creating UUID while serving POST /newuser : ", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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

	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
	
func NotFound(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/notfound.html")
}

func UserFromUUID(UUID string) string {
	statement, _ := sessiondb.Prepare("SELECT username FROM sessions WHERE UUID=?")
	var username string

	err := statement.QueryRow(UUID).Scan(&username)

	if err != nil {
		fmt.Println("Error obtaining username from UUID : ", err)
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

	router.GET("/",			GetRoot)
	router.GET("/saveurl",	RedirectWrapper("static/saveurl"))
	router.POST("/saveurl", PostSaveURL)
	router.GET("/account",	GetViewURLs)
	router.GET("/login",	GetLogin)
	router.POST("/login",	PostLogin)
	router.GET("/newuser",	GetNewUser)
	router.POST("/newuser",	PostNewUser)
	router.ServeFiles("/pages/*filepath", http.Dir("static/"))


	fmt.Println("Server started on port 8080")
	fmt.Println(http.ListenAndServe(":8080", router))
//	TLS keys might be difficult to generate
//	fmt.Println(http.ListenAndServeTLS(":8080", "tls/cert.pem", "tls/privkey.pem", router))
}
