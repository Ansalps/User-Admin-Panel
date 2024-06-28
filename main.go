package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type errors struct {
	UsernameError string
	PasswordError string
}
type SignupError struct {
	// InvalidFullName string
	InvalidUsername string
	//InvalidEmail string
	InvalidPhone    string
	InvalidPassword string
	// InvalidGender string
	InvalidSignUp string
}

var InvalidSignData SignupError

type SignupUsers struct {
	FullName       string `gorm:"not null"`
	NewUsername    string `gorm:"primarykey"`
	NewEmail       string `gorm:"not null"`
	NewPhone       string `gorm:"not null;"`
	SignupPassword string `gorm:"not null"`
	Gender         string `gorm:"not null"`
}

var a1 SignupUsers

type PageData struct {
	PassError SignupError
	PassTable SignupUsers
}

type home struct {
	Username2 string
}

var errorV errors
var h home
var username string
var sessions = make(map[string]string)

// var sessionID string
// var sessionCookie http.Cookie
var c http.Cookie
var db *gorm.DB
var err error

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
	Username string `json:"username"`
	Role     string
	jwt.StandardClaims
}

func createToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(60 * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func parseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}
	//claim := token.Claims.(*Claims)

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		fmt.Println("Username:", claims.Username)
		fmt.Println("Role:", claims.Role)
		fmt.Println("Issued At:", time.Unix(claims.IssuedAt, 0))
	} else {
		fmt.Println("Invalid token")
	}
	// if claim.Role != "admin" {
	// 	return nil, nil
	// }
	return token, nil
}

func middleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve JWT token from the cookie
		cookie, err := r.Cookie("jwt_admin_token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Missing authorization cookie")
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Error retrieving cookie: %v", err)
			return
		}

		tokenString := cookie.Value
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Missing authorization token")
			return
		}

		token, err := parseToken(tokenString)
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Invalid authorization token: %v", err)
			return
		}

		// claims := token.Claims.(*Claims)
		// role:=claims.Role
		// username:=claims.Username
		// if role=="admin" {}
		// role, val := token.Claims

		next.ServeHTTP(w, r)
	})
}

func main() {
	dsn := "postgres://postgres:123@localhost:5432/week6"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	fmt.Println(db)

	if err != nil {
		fmt.Println("connection failed due to ", err)
	}
	db.AutoMigrate(&SignupUsers{})

	http.HandleFunc("/", rootHandler)
	//http.HandleFunc("/login", formHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/home", homeHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/admin", admin)
	http.Handle("/adminAddUser", middleWare(http.HandlerFunc(adminAddUser)))
	http.Handle("/adminUserUpdate", middleWare(http.HandlerFunc(adminUserUpdate)))
	http.Handle("/adminSearchUser", middleWare(http.HandlerFunc(adminSearchUser)))
	http.HandleFunc("/adminLogout", adminLogout)

	// http.HandleFunc("/adminUserUpdated", adminUserUpdated)
	http.Handle("/adminUserDelete", middleWare(http.HandlerFunc(adminUserDelete)))
	fmt.Printf("Starting server at port 5500\n")
	if err := http.ListenAndServe(":5500", nil); err != nil {
		log.Fatal(err)
	}

}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	// errorV.UsernameError = ""
	// errorV.PasswordError = ""
	// firstNumValues := len(r.Form)
	// fmt.Println("form param number ", firstNumValues)
	//w.Header().Set("Cache-Control", "no-cache,no-store,must-revalidate")
	if r.Method == "POST" && len(r.Form) < 3 {
		w.Header().Set("Cache-Control", "no-store")

		var username1 string
		var password1 string
		if err := r.ParseForm(); err != nil {
			fmt.Println("error here", err)
			http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
			return
		}
		username = r.FormValue("username")
		password := r.FormValue("password")
		fmt.Println("-", username)
		fmt.Println("--", password)

		if username == "admin" && password == "admin" {
			errorV.UsernameError = ""
			errorV.PasswordError = ""
			tokenString, err := createToken(username, "admin")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Error creating token: %v", err)
				return
			}
			fmt.Printf("Token: %s\n", tokenString)
			cookie := http.Cookie{
				Name:     "jwt_admin_token",
				Value:    tokenString,
				Expires:  time.Now().Add(24 * time.Hour), // Set cookie expiration time
				HttpOnly: true,                           // Cookie accessible only by HTTP requests
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)

			return
		}
		var count int64
		db.Model(&SignupUsers{}).Where("new_username = ?", username).Count(&count)
		if count != 0 {
			fmt.Println("username exists")
			db.Model(&SignupUsers{}).Where("new_username = ?", username).Pluck("new_username", &username1)
			db.Model(&SignupUsers{}).Where("new_username = ?", username).Pluck("signup_password", &password1)
			fmt.Println("username1 ", username1)
			fmt.Println("password1 ", password1)
		}
		fmt.Println("---", username1)
		fmt.Println("----", password1)

		if username1 == username && password1 == password && username != "" && password != "" {
			// fmt.Println("success in formHandler")
			// // Set the new cookie with the expiration time in the past
			// sessionID = strconv.FormatInt(rand.Int63(), 16)

			// sessionCookie = http.Cookie{Name: username, Value: sessionID}
			// http.SetCookie(w, &sessionCookie)
			// fmt.Println(sessionCookie)

			// //sessionCookie = &c
			// sessions[username] = sessionID

			// fmt.Printf("session created with session id %s and session data %v\n", sessionID, sessions[sessionID])
			errorV.UsernameError = ""
			errorV.PasswordError = ""
			tokenString, err := createToken(username, "user")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Error creating token: %v", err)
				return
			}
			fmt.Printf("Token: %s\n", tokenString)
			cookie := http.Cookie{
				Name:     "jwt_token",
				Value:    tokenString,
				Expires:  time.Now().Add(24 * time.Hour), // Set cookie expiration time
				HttpOnly: true,                           // Cookie accessible only by HTTP requests
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/home", http.StatusSeeOther)
		} else if username1 != username && password1 == password {
			errorV.UsernameError = "Invalid username"
			errorV.PasswordError = ""
			//tmp, _ := template.ParseFiles("index.html")
			//tmp.ExecuteTemplate(w, "index.html", errorV)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else if password1 != password && username1 == username {
			errorV.PasswordError = "Invalid password"
			errorV.UsernameError = ""
			//tmp, _ := template.ParseFiles("index.html")
			//tmp.ExecuteTemplate(w, "index.html", errorV)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			errorV.UsernameError = "Invalid username"
			errorV.PasswordError = "Invalid password"
			//tmp, _ := template.ParseFiles("index.html")
			//tmp.ExecuteTemplate(w, "index.html", errorV)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}

	}
	fmt.Println("success in rootHandler")
	fmt.Println(username)

	_, err := r.Cookie("jwt_token")
	if err == nil { //means cookie here
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	a, err := r.Cookie("jwt_admin_token")
	if err == nil { //means cookie here
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
	fmt.Println(a)

	tmp, err := template.ParseFiles("index.html")
	if err != nil {
		log.Fatalf("error %v", err)
	}
	tmp.ExecuteTemplate(w, "index.html", errorV)
	fmt.Println("out of rootHandler")
}

type PageSearchData struct {
	UserAdminList []SignupUsers
	SearchError   string
}

func adminSearchUser(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Cache-Control", "no-store")
	fmt.Println("success in adminSearchUser")
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			fmt.Println("error here", err)
			http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
			return
		}
		var usersNaming []SignupUsers
		//query := db
		//if searchCriteria.Name != "" {
		query := db.Where("new_username LIKE ?", "%"+r.FormValue("usernaming")+"%")
		//}
		query.Find(&usersNaming)
		data := PageSearchData{
			UserAdminList: usersNaming,
		}
		if len(usersNaming) == 0 {
			data.SearchError = "No users found"
		}
		tpl, err := template.ParseFiles("admin.html")
		if err != nil {
			fmt.Println("error in search parsing", err)
			return
		}

		err = tpl.Execute(w, data)
		if err != nil {
			fmt.Println("error in search execute ", err)
			return
		}
	}
}
func adminAddUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fmt.Println("success in adminAddUser")
	if r.Method == "POST" {
		fmt.Println("succes in adminadduser post")
		if err := r.ParseForm(); err != nil {
			fmt.Println("error here", err)
			http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
			return
		}
		a1.FullName = r.FormValue("formName")
		a1.NewUsername = r.FormValue("formUsername")
		a1.NewEmail = r.FormValue("formEmail")
		a1.NewPhone = r.FormValue("formPhonNumber")
		a1.SignupPassword = r.FormValue("formPassword")
		a1.Gender = r.FormValue("gender")
		if a1.FullName == "" || a1.NewUsername == "" || a1.NewEmail == "" || a1.NewPhone == "" || a1.SignupPassword == "" || a1.Gender == "" {
			InvalidSignData.InvalidSignUp = "Invalid data in sign up"
			InvalidSignData.InvalidUsername = "Invalid data in sign up"
			InvalidSignData.InvalidPhone = "Invalid data in sign up"
			InvalidSignData.InvalidPassword = ""
			tmp, err := template.ParseFiles("Responsive Registration Form/adminAddUserSignUp.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			tmp.ExecuteTemplate(w, "adminAddUserSignUp.html", InvalidSignData)
			return
		}
		//db.Create(a1)
		fmt.Println("length of phone ", len(a1.NewPhone))
		if len(a1.NewPhone) != 10 {
			fmt.Println("kiki")
			InvalidSignData.InvalidSignUp = ""
			InvalidSignData.InvalidUsername = ""
			InvalidSignData.InvalidPhone = "phone number must be 10 digits"
			InvalidSignData.InvalidPassword = ""
			tmp, err := template.ParseFiles("Responsive Registration Form/adminAddUserSignUp.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			err = tmp.ExecuteTemplate(w, "adminAddUserSignUp.html", InvalidSignData)
			if err != nil {
				fmt.Println("---", err)
			}
			return
		}
		var count int64
		db.Model(&SignupUsers{}).Where("new_username = ?", a1.NewUsername).Count(&count)
		if count != 0 {
			InvalidSignData.InvalidUsername = "Already registered Username"
			InvalidSignData.InvalidSignUp = ""
			tmp, err := template.ParseFiles("Responsive Registration Form/adminAddUserSignUp.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			tmp.ExecuteTemplate(w, "adminAddUserSignUp.html", InvalidSignData)
			return
		}
		fmt.Println("hi")
		query := "INSERT INTO signup_users (full_name,new_username,new_email,new_phone,signup_password,gender) VALUES ($1,$2,$3,$4,$5,$6)"
		err = db.Exec(query, a1.FullName, a1.NewUsername, a1.NewEmail, a1.NewPhone, a1.SignupPassword, a1.Gender).Error
		fmt.Println("query executed")
		if err != nil {
			fmt.Println("does query have error")
			fmt.Println("err:", err)
			tmp, err := template.ParseFiles("Responsive Registration Form/adminAddUserSignUp.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			tmp.ExecuteTemplate(w, "adminAddUserSignUp.html", "uihdfsiojiofdsiiojdsfiojdfsioj")
			return
		}
		fmt.Println("does it reach after error")
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
	tmp, err := template.ParseFiles("Responsive Registration Form/adminAddUserSignUp.html")
	if err != nil {
		log.Fatalf("error %v", err)
	}
	// fmt.Println("---------", h)
	tmp.ExecuteTemplate(w, "adminAddUserSignUp.html", nil)

}

var StoreUsername string

func adminUserUpdate(w http.ResponseWriter, r *http.Request) {
	//StoreUsername = r.FormValue("usingNameToUpdate")
	//w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		fmt.Println("error here", err)
		http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
		return
	}
	numValues := len(r.Form)
	fmt.Println("form value number ", numValues)
	// PassData := PageData{
	// 	PassError: InvalidSignData,
	// 	PassTable: a1,
	// }
	fmt.Println("hi")

	if r.Method == "POST" && numValues == 1 {
		var PassData PageData
		var user SignupUsers
		fmt.Println("succes in adminUpdateUser post")

		fmt.Println(r.FormValue("usingNameToUpdate"))
		//ForForm:=r.FormValue("usingNameToUpdate")
		InvalidSignData.InvalidUsername = ""
		InvalidSignData.InvalidSignUp = ""

		//var ToForm SignupUsers
		fmt.Println("----", r.FormValue("usingNameToUpdate"))
		// if err := db.Where("new_username = ?", r.FormValue("usingNameToUpdate")).Order("new_username").First(&PassData.PassTable).Error; err != nil {
		// 	fmt.Println("Record not found")
		// 	return
		// }

		if err := db.Raw("SELECT * FROM signup_users WHERE new_username = ?", r.FormValue("usingNameToUpdate")).Scan(&user).Error; err != nil {
			// Handle the error
			fmt.Println("Error:", err)
			return
		}
		fmt.Println("phone number ", user.NewPhone)
		//user.NewPhone
		PassData = PageData{
			PassError: InvalidSignData,
			PassTable: user,
		}

		fmt.Println("not workin", PassData.PassTable.FullName)
		tmp, err := template.ParseFiles("Responsive Registration Form/adminUpdateUserSignUp.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tmp.Execute(w, PassData); err != nil {
			fmt.Println("---", err)
			return
		}
	}
	if r.Method == "POST" && numValues > 1 {
		var PassData PageData
		var user SignupUsers
		fmt.Println("2nd post")
		a1.FullName = r.FormValue("formName")
		a1.NewUsername = r.FormValue("formUsername")
		fmt.Println(a1.FullName)
		a1.NewEmail = r.FormValue("formEmail")
		a1.NewPhone = r.FormValue("formPhonNumber")
		a1.SignupPassword = r.FormValue("formPassword")
		a1.Gender = r.FormValue("gender")

		if a1.FullName == "" || a1.NewEmail == "" || a1.NewPhone == "" || a1.SignupPassword == "" || a1.Gender == "" {
			InvalidSignData.InvalidSignUp = "Invalid data in sign up"
			InvalidSignData.InvalidUsername = "Invalid data in sign up"
			InvalidSignData.InvalidPhone = ""
			fmt.Println("does nil condition work")
			if err := db.Raw("SELECT * FROM signup_users WHERE new_username = ?", a1.NewUsername).Scan(&user).Error; err != nil {
				// Handle the error
				fmt.Println("Error:", err)
				return
			}
			PassData = PageData{
				PassError: InvalidSignData,
				PassTable: user,
			}

			fmt.Println("---", PassData.PassTable.FullName)
			fmt.Println("----", PassData.PassError.InvalidSignUp)
			tmp, err := template.ParseFiles("Responsive Registration Form/adminUpdateUserSignUp.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			err = tmp.ExecuteTemplate(w, "adminUpdateUserSignUp.html", PassData)
			if err != nil {
				fmt.Println("-------", err)
				return
			}
			return
		}
		if len(a1.NewPhone) != 10 {
			InvalidSignData.InvalidSignUp = ""
			InvalidSignData.InvalidUsername = ""
			InvalidSignData.InvalidPhone = "phone number must be 10 digits"
			fmt.Println("does nil condition work")
			if err := db.Raw("SELECT * FROM signup_users WHERE new_username = ?", a1.NewUsername).Scan(&user).Error; err != nil {
				// Handle the error
				fmt.Println("Error:", err)
				return
			}
			PassData = PageData{
				PassError: InvalidSignData,
				PassTable: user,
			}

			fmt.Println("---", PassData.PassTable.FullName)
			fmt.Println("----", PassData.PassError.InvalidSignUp)
			tmp, err := template.ParseFiles("Responsive Registration Form/adminUpdateUserSignUp.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			err = tmp.ExecuteTemplate(w, "adminUpdateUserSignUp.html", PassData)
			if err != nil {
				fmt.Println("-------", err)
				return
			}
			return
		}

		//db.Create(a1)

		// var count int64
		// db.Model(&SignupUsers{}).Where("new_username = ?", a1.NewUsername).Count(&count)
		// if count != 0 {
		// 	InvalidSignData.InvalidUsername = "Already registered Username"
		// 	InvalidSignData.InvalidSignUp = ""
		// 	tmp, err := template.ParseFiles("Responsive Registration Form/admiUpdateUserSignUp.html")
		// 	if err != nil {
		// 		log.Fatalf("error %v", err)
		// 	}
		// 	// fmt.Println("---------", h)
		// 	tmp.ExecuteTemplate(w, "adminUpdateUserSignUp.html", InvalidSignData)
		// 	return
		// }
		fmt.Println("hi")
		fmt.Println("----", a1.NewUsername)
		//query := "UPDATE signup_users SET full_name=$1,new_email=$2,new_phone=$3,signup_password=$4,gender=$5 WHERE new_username= VALUES (,,,,)"
		//err = db.Exec(query, a1.FullName, a1.NewUsername, a1.NewEmail, a1.NewPhone, a1.SignupPassword, a1.Gender).Error
		results := db.Model(&SignupUsers{}).Where("new_username = ?", a1.NewUsername).Updates(map[string]interface{}{
			"full_name":       a1.FullName,
			"new_email":       a1.NewEmail,
			"new_phone":       a1.NewPhone,
			"signup_password": a1.SignupPassword,
			"gender":          a1.Gender,
		})
		//fmt.Println("query executed")
		if results.Error != nil {
			fmt.Println("does query have error")
			fmt.Println("err:", results.Error)
		}
		// tmp, err := template.ParseFiles("Responsive Registration Form/adminUpdateUserSignUp.html")
		// if err != nil {
		// 	log.Fatalf("error %v", err)
		// }
		// tmp.ExecuteTemplate(w, "adminUpdateUserSignUp.html", "uihdfsiojiofdsiiojdsfiojdfsioj")
		// return

		fmt.Println("does it reach after error")
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
	if r.Method == "GET" {
		fmt.Println("gee")
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
}

// tmp, err := template.ParseFiles("Responsive Registration Form/adminAddUserSignUp.html")
// if err != nil {
// 	log.Fatalf("error %v", err)
// }
// // fmt.Println("---------", h)
// tmp.ExecuteTemplate(w, "adminAddUserSignUp.html", nil)
// 	}
// 	return
// }

// func adminUserUpdated(w http.ResponseWriter, r *http.Request)  {

// }
func adminUserDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "POST" {
		fmt.Println("succes in adminDeleteUser post")
		if err := r.ParseForm(); err != nil {
			fmt.Println("error here", err)
			http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
			return
		}
		fmt.Println(r.FormValue("usingNameToDelete"))
		db.Where("new_username", r.FormValue("usingNameToDelete")).Delete(&SignupUsers{})
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	} else {
		http.Error(w, "404 not found.", http.StatusNotFound)
	}
}
func admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	//if r.Method == "post" {
	_, err := r.Cookie("jwt_admin_token")
	if err != nil { //no cookie
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	fmt.Println("success in admin")
	fmt.Println("success in admin post")
	var Userlist []SignupUsers
	db.Find(&Userlist)
	data := PageSearchData{
		UserAdminList: Userlist,
	}
	if len(Userlist) == 0 {
		data.SearchError = "No users found"
	}
	// Parse the template file
	tmp, err := template.ParseFiles("admin.html")
	if err != nil {
		fmt.Printf("error parsing template file: %v\n", err)
	}

	//fmt.Println("*******************", Userlist)

	// Execute the template with the data
	err = tmp.Execute(w, data)
	if err != nil {
		log.Fatalf("error executing template: %v", err)
	}
	// } else {
	// 	http.Error(w, "404 not found.", http.StatusNotFound)
	// }
}
func signupHandler(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Cache-Control", "no-store")
	errorV.UsernameError = ""
	errorV.PasswordError = ""
	fmt.Println("success in signupHandler")
	if r.Method == "POST" {
		w.Header().Set("Cache-Control", "no-store")
		if err := r.ParseForm(); err != nil {
			fmt.Println("error here", err)
			http.Error(w, "Failed to parse form data", http.StatusInternalServerError)
			return
		}
		a1.FullName = r.FormValue("formName")
		a1.NewUsername = r.FormValue("formUsername")
		a1.NewEmail = r.FormValue("formEmail")
		a1.NewPhone = r.FormValue("formPhonNumber")
		a1.SignupPassword = r.FormValue("formPassword")
		a1.Gender = r.FormValue("gender")
		if a1.FullName == "" || a1.NewUsername == "" || a1.NewEmail == "" || a1.NewPhone == "" || a1.SignupPassword == "" || a1.Gender == "" {
			InvalidSignData.InvalidSignUp = "Invalid data in sign up"
			InvalidSignData.InvalidUsername = "Invalid data in sign up"
			InvalidSignData.InvalidPassword = "Invalid data in sign up"
			InvalidSignData.InvalidPhone = "Invalid data in sign up"
			tmp, err := template.ParseFiles("Responsive Registration Form/signup.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			tmp.ExecuteTemplate(w, "signup.html", InvalidSignData)
			return
		}
		if a1.SignupPassword != r.FormValue("formConfirmPassword") {
			InvalidSignData.InvalidSignUp = ""
			InvalidSignData.InvalidUsername = ""
			InvalidSignData.InvalidPhone = ""
			InvalidSignData.InvalidPassword = "two password must match"
			tmp, err := template.ParseFiles("Responsive Registration Form/signup.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			tmp.ExecuteTemplate(w, "signup.html", InvalidSignData)
			return
		}
		fmt.Println("length of phone ", len(a1.NewPhone))
		if len(a1.NewPhone) != 10 {
			InvalidSignData.InvalidSignUp = ""
			InvalidSignData.InvalidUsername = ""
			InvalidSignData.InvalidPassword = ""
			InvalidSignData.InvalidPhone = "phone number must be 10 digits"
			tmp, err := template.ParseFiles("Responsive Registration Form/signup.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			tmp.ExecuteTemplate(w, "signup.html", InvalidSignData)
			return
		}
		//db.Create(a1)

		var count int64
		db.Model(&SignupUsers{}).Where("new_username = ?", a1.NewUsername).Count(&count)
		if count != 0 {
			InvalidSignData.InvalidUsername = "Already registered Username"
			InvalidSignData.InvalidSignUp = ""
			tmp, err := template.ParseFiles("Responsive Registration Form/signup.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			// fmt.Println("---------", h)
			tmp.ExecuteTemplate(w, "signup.html", InvalidSignData)
			return
		}

		query := "INSERT INTO signup_users (full_name,new_username,new_email,new_phone,signup_password,gender) VALUES ($1,$2,$3,$4,$5,$6)"
		err = db.Exec(query, a1.FullName, a1.NewUsername, a1.NewEmail, a1.NewPhone, a1.SignupPassword, a1.Gender).Error

		if err != nil {
			fmt.Println("err:", err)
			tmp, err := template.ParseFiles("Responsive Registration Form/signup.html")
			if err != nil {
				log.Fatalf("error %v", err)
			}
			tmp.ExecuteTemplate(w, "signup.html", "uihdfsiojiofdsiiojdsfiojdfsioj")
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	_, err := r.Cookie("jwt_token")
	if err == nil { //means cookie here
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	a, err := r.Cookie("jwt_admin_token")
	if err == nil { //means cookie here
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
	fmt.Println(a)
	tmp, err := template.ParseFiles("Responsive Registration Form/signup.html")
	if err != nil {
		log.Fatalf("error %v", err)
	}
	fmt.Println("---------", h)
	tmp.ExecuteTemplate(w, "signup.html", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fmt.Println("success in homeHandler")
	fmt.Println(username)
	_, err := r.Cookie("jwt_token")
	if err != nil { //no cookie
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	h.Username2 = username
	tmp, err := template.ParseFiles("home.html")
	if err != nil {
		log.Fatalf("error %v", err)
	}
	fmt.Println("---------", h)
	tmp.ExecuteTemplate(w, "home.html", h)
	fmt.Println("out of homeHandler")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		//w.Header().Set("Cache-Control", "no-cache,no-store,must-revalidate")

		c = http.Cookie{Name: "jwt_token", Value: "", Expires: time.Now().AddDate(0, 0, -1), MaxAge: -1}

		http.SetCookie(w, &c)

		delete(sessions, username)

		fmt.Println("in logoutHandler")
		fmt.Printf("%v\n", sessions)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Error(w, "404 not found.", http.StatusNotFound)
	}
}

func adminLogout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("success in adminLogout")
	if r.Method == "POST" {
		fmt.Println("inside post of admin logout")
		fmt.Println("hi--hello")
		//if r.Method == "POST" {
		c = http.Cookie{Name: "jwt_admin_token", Value: "", Expires: time.Now().AddDate(0, 0, -1), MaxAge: -1}

		http.SetCookie(w, &c)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		//} else {
		//http.Error(w, "404 not found.", http.StatusNotFound)
		//}
	} else {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	fmt.Println("out of admin Logout")

}
