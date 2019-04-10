package main
import (
	"github.com/gin-contrib/cors"
	"crypto/rand"
	"io/ioutil"
	"fmt"
	"net/http"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"context"
	"encoding/json"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/mgo.v2"
	"strings"
	"encoding/base32"
	"golang.org/x/oauth2/vk"
	"strconv"
	"net/smtp"
	"log"
	"github.com/goware/emailx"
)



type User struct {
	ID   bson.ObjectId `bson:"_id"`
	Sub    string   `bson:"sub"`
	Email string  `bson:"email"`
	Username string `bson:"username"`
	Wins int `bson:"wins"`
	Loses int `bson:"loses"`
	Password string `bson:"password"`
}
type Level struct {
	Code string `bson:"code"`
}
type winrate struct {
	Loses              int `bson:"loses"`
	Wins               int `bson:"wins"`
	M_modern_wins      int `bson:"m_modern_wins"`
	M_modern_pvp_wins  int `bson:"m_modern_pvp_wins"`
	M_classic_wins     int `bson:"m_classic_wins"`
	M_classic_pvp_wins int `bson:"m_classic_pvp_wins"`
	P_classic_wins     int `bson:"p_classic_wins"`
	P_classic_pvp_wins int `bson:"p_classic_pvp_wins"`
	P_modern_wins      int `bson:"p_modern_wins"`
	P_modern_pvp_wins  int `bson:"p_modern_pvp_wins"`
	M_point_wins       int `bson:"m_point_wins"`
	M_point_pvp_wins   int `bson:"m_point_pvp_wins"`
	P_point_wins       int `bson:"p_point_wins"`
	P_point_pvp_wins   int `bson:"p_point_pvp_wins"`
	M_modern_losses      int `bson:"m_modern_losses"`
	M_modern_pvp_losses int `bson:"m_modern_pvp_losses"`
	M_classic_losses     int `bson:"m_classic_losses"`
	M_classic_pvp_losses int `bson:"m_classic_pvp_losses"`
	P_classic_losses     int `bson:"p_classic_losses"`
	P_classic_pvp_losses int `bson:"p_classic_pvp_losses"`
	P_modern_losses      int `bson:"p_modern_losses"`
	P_modern_pvp_losses  int `bson:"p_modern_pvp_losses"`
	M_point_losses       int `bson:"m_point_losses"`
	M_point_pvp_losses   int `bson:"m_point_pvp_losses"`
	P_point_losses       int `bson:"p_point_losses"`
	P_point_pvp_losses   int `bson:"p_point_pvp_losses"`
}
type LeaderBoard_data struct {
	Username string `bson:"username"`
	Wins int `bson:"wins"`
}

var conf *oauth2.Config
var conf2 *oauth2.Config
var Online string
var Games_Played int
func add_mongodb (user *User ){
	if err := coll.Insert(user); err != nil {
		panic(err)
	}
}
func randToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}
func send_email(body string,to string) {
	from := ".....@gmail.com"
	pass := "......."

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Registration\n\n" +
		body

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}

}

func init() {

	conf = &oauth2.Config{
		ClientID:     ".......",
		ClientSecret: ".................",
		RedirectURL:  "https://backend.4battle.ru:8080/google",
		Scopes:       []string{"email", "profile"},
		Endpoint: google.Endpoint,
	}
	conf2=&oauth2.Config{
		ClientID:     "......",
		ClientSecret: "...............",
		RedirectURL:  "https://backend.4battle.ru:8080/vk",
		Endpoint: vk.Endpoint,
	}
}



func googleHandler(c *gin.Context) {
	session := sessions.Default(c)
	ID := session.Get("id")
	if ID!=nil{
		c.Redirect(http.StatusMovedPermanently, "https://4battle.ru/")
		return
	}
	var data map[string]interface{}
	token, err := conf.Exchange(context.Background(), c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	client := conf.Client(context.Background(), token)
	response, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
//Info from google
	defer response.Body.Close()
	responseText, _ := ioutil.ReadAll(response.Body)
	_ = json.Unmarshal([]byte(responseText), &data)
	count, err := coll.Find(bson.M{"sub": data["sub"].(string)}).Count() //check if account exists
var user1 User
	if count==0{  //if not exists
		Token:=randToken()
		user1 = User{bson.NewObjectId(),data["sub"].(string),data["email"].(string),"",0,0,""}
		TokenToUser[Token]=user1
		c.Redirect(http.StatusMovedPermanently, "https://4battle.ru/?Token="+Token)
	}else{ //if  exists
		session := sessions.Default(c)
		err = coll.Find(bson.M{"sub": data["sub"].(string)}).One(&user1) //get object id by google id
		session.Set("id",user1.ID.Hex())
		session.Set("username",user1.Username)
		session.Save()
		c.Redirect(http.StatusMovedPermanently, "https://4battle.ru/")
	}


}
func vkHandler(c *gin.Context) {
	session := sessions.Default(c)
	ID := session.Get("id")
	if ID!=nil{
		c.Redirect(http.StatusMovedPermanently, "https://4battle.ru/")
		return
	}
	token, err := conf2.Exchange(context.Background(), c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	var user_id= token.Extra("user_id")
	user_id=strconv.FormatFloat(user_id.(float64), 'f', -1, 64)
	var email=token.Extra("email")
	if email==nil{
		email="no Email"
	}

	count, err := coll.Find(bson.M{"sub": user_id.(string)}).Count()  //check if account exists
	var user1 User
	if count==0{
		Token:=randToken()
		user1 = User{bson.NewObjectId(),user_id.(string),email.(string),"",0,0,""}
		TokenToUser[Token]=user1
		c.Redirect(http.StatusMovedPermanently, "https://4battle.ru/?Token="+Token)
	}else{
		session := sessions.Default(c)
		err = coll.Find(bson.M{"sub":user_id.(string)}).One(&user1)
		session.Set("id",user1.ID.Hex())
		session.Set("username",user1.Username)
		session.Save()
		c.Redirect(http.StatusMovedPermanently, "https://4battle.ru/")
	}


}
func loginGoogleHandler(c *gin.Context) {
	c.Redirect(http.StatusMovedPermanently, "https://accounts.google.com/o/oauth2/auth?client_id=883953263430-fk5i1q5l1d38ispg5a56o9n3bpo0j1m7.apps.googleusercontent.com&redirect_uri=https://backend.4battle.ru:8080/google&response_type=code&scope=email+profile")
}
func loginVkHandler(c *gin.Context) {
	c.Redirect(http.StatusMovedPermanently, "https://oauth.vk.com/authorize?client_id=6156000&response_type=code&redirect_uri=https://backend.4battle.ru:8080/vk&scope=email")
}
func change_usernameHandler(c *gin.Context) {
	Token := c.PostForm("Token")
	user2, ok := TokenToUser[Token]
	var count2 int;
		if ok {
			name := c.PostForm("name")
			name = strings.Trim(name, " ")
              if name != "" {
				count, err := coll.Find(bson.M{"username": bson.RegEx{Pattern: "^" + name + "$", Options: "i"}}).Count()
				if user2.Sub=="no sub"{
				  count2=0
				}else{
					count2, err = coll.Find(bson.M{"sub": user2.Sub}).Count()
				}
				if err != nil {
					panic(err)
				}
				fmt.Println(count)
				if count == 0 && count2==0 {
					fmt.Println("user registered")
					session := sessions.Default(c)
					user2.Username = name
					add_mongodb(&user2)
					fmt.Println(name)
					session.Set("id", user2.ID.Hex())
					session.Set("username",user2.Username)
					session.Save()
					delete(TokenToUser, Token)
					c.String(200, "1")
				}
			}
		}

}
func checkHandler(c *gin.Context) {
	session := sessions.Default(c)
	Username := session.Get("username")
	if Username==nil{
		c.String(200, "0")
		return
	}
	c.String(200, Username.(string))

}

func post_level_Handler(c *gin.Context) {
	var level Level
	level.Code = c.PostForm("code")
	if err := Level_collumn.Insert(level); err != nil {
		panic(err)
	}
	c.String(200,"1")
}
func get_levels_Handler(c *gin.Context) {
	var result []Level
	err := Level_collumn.Find(nil).Select(bson.M{"code": 1,"_id":0}).All(&result)
	if err != nil {
		// handle error
	}
	b, _ := json.Marshal(result)
	c.String(200,string(b))
}
func player_winner_db_Handler(c *gin.Context) {
	username := c.PostForm("username")
	count, _ := coll.Find(bson.M{"username": bson.RegEx{Pattern: "^" + username + "$", Options: "i"}}).Count()
	if count==0{
		c.String(200,"1")
        Games_Played++;
          return
	}  
	mode := c.PostForm("mode")
	query := bson.M{"username": username}
	update := bson.M{"$inc": bson.M{"wins": 1}}
	update2 := bson.M{"$inc": bson.M{mode: 1}}
    err = coll.Update(query, update)
	err = coll.Update(query, update2)
if err != nil {
panic(err)
}
	c.String(200,"1")
	Games_Played++
}
func match_end_Handler(c *gin.Context) {
	usernames := []string{}
	data := c.PostForm("usernames")
	mode := c.PostForm("mode")
	_ = json.Unmarshal([]byte(data), &usernames)
	fmt.Println(len(usernames))
	for i := 0; i < len(usernames); i++ {
       count, _ := coll.Find(bson.M{"username": bson.RegEx{Pattern: "^" + usernames[i] + "$", Options: "i"}}).Count()
       if count==0{
       	continue
	    }  
		query := bson.M{"username": usernames[i]}
		update := bson.M{"$inc": bson.M{"loses": 1}}
		err = coll.Update(query, update)
		update2 := bson.M{"$inc": bson.M{mode: 1}}
	    err = coll.Update(query, update2)
		if err != nil {
			panic(err)
		}
	}
	
	c.String(200,"1")
}
func login_signUp_Email_Handler(c *gin.Context) {
	email := strings.Trim(c.PostForm("email"), " ")
	password := strings.Trim(c.PostForm("password"), " ")
	err := emailx.Validate(email)
	if err!=nil || password==""{
		return
	}
	count, err := coll.Find(bson.M{"email": email}).Count()
	if err != nil {
		panic(err)
	}
	var user1 User
	if count==0{  //if not exists
		Token:=randToken()
		user1 = User{bson.NewObjectId(),"no sub",email,"",0,0,password}
		TokenToUser[Token]=user1
		link:="https://4battle.ru/?Token="+Token
		send_email("To continue registration follow this link "+link,email)
		c.String(200,"1")
	}else{ //if  exists
		err = coll.Find(bson.M{"email": email}).One(&user1) //get object id by google id
		if user1.Password==password {
			session := sessions.Default(c)
			session.Set("id",user1.ID.Hex())
			session.Set("username",user1.Username)
			session.Save()
			c.String(200,"2")
		}

	}

}
func online_push_Handler(c *gin.Context) {
	online_count := c.PostForm("online")
	Online=online_count
	fmt.Println(online_count)
}
func onlineHandler(c *gin.Context) {
	c.String(200,Online)
}
func winrateHandler(c *gin.Context) {
	var winrate=winrate{}
	session := sessions.Default(c)
	Username := session.Get("username")
	if Username==nil{
		return
	}
	err = coll.Find(bson.M{"username":Username}).Select(bson.M{"wins": 1,"loses": 1,"m_modern_losses": 1,"m_modern_pvp_losses": 1,"m_classic_losses": 1,"m_classic_pvp_losses": 1,"p_classic_losses": 1,"p_classic_pvp_losses": 1,"p_modern_losses": 1,"p_modern_pvp_losses": 1,"m_point_losses": 1,"m_point_pvp_losses": 1,"p_point_losses": 1,"p_point_pvp_losses": 1,"m_modern_wins": 1,"m_modern_pvp_wins": 1,"m_classic_wins": 1,"m_classic_pvp_wins": 1,"p_classic_wins": 1,"p_classic_pvp_wins": 1,"p_modern_wins": 1,"p_modern_pvp_wins": 1,"m_point_wins": 1,"m_point_pvp_wins": 1,"p_point_wins": 1,"p_point_pvp_wins": 1,"_id":0}).One(&winrate)
    fmt.Println(winrate)
	data,_ := json.Marshal(winrate)
	c.String(200,string(data))
}
func checkTopWinnersHandler(c *gin.Context) {
	var Users []LeaderBoard_data
	err = coll.Find(nil).Sort("-wins").Limit(20).All(&Users)
	data, err := json.Marshal(Users)
	if err != nil {
		// handle error
	}
	c.String(200,string(data))
}
func Games_PlayedHandler(c *gin.Context) {
	c.String(200,strconv.Itoa(Games_Played))
}
func check_username_Handler(c *gin.Context) {
name := c.PostForm("name")
name = strings.Trim(name, " ")
if name != "" {
count, _ := coll.Find(bson.M{"username": bson.RegEx{Pattern: "^" + name + "$", Options: "i"}}).Count()
c.String(200,strconv.Itoa(count))
}
}
func LogOutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Set("id",nil)
	session.Set("username",nil)
	session.Save()
	c.Redirect(http.StatusTemporaryRedirect, "https://4battle.ru")
}
var mongodb,err=mgo.Dial("127.0.0.1")
var coll = mongodb.DB("TicTacToe_Auth").C("Users")
var Level_collumn = mongodb.DB("TicTacToe_Auth").C("Levels")
var TokenToUser=map[string]User{}
func main() {
	if err != nil {
		panic(err)
	}
  defer mongodb.Close()

  Online="0"
  Games_Played=0
	store, _ := sessions.NewRedisStore(10, "tcp", "127.0.0.1:6379", "", []byte("........."))
	var x  sessions.Options
	x.HttpOnly=true
	x.MaxAge=2592000
	store.Options(x)
	router := gin.Default()
	router.Use(sessions.Sessions("Auth", store))
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://4battle.ru"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))
	//public
	router.GET("/login_google", loginGoogleHandler)
	router.GET("/login_vk", loginVkHandler)
	router.GET("/google", googleHandler)
	router.GET("/vk", vkHandler)
	router.POST("/change_username", change_usernameHandler)
	router.GET("/leaderboard", checkTopWinnersHandler)
	router.GET("/check",checkHandler)
	router.GET("/winrate", winrateHandler)
	router.GET("/online", onlineHandler)
	router.GET("/Games_Played", Games_PlayedHandler)
	router.POST("/by_email", login_signUp_Email_Handler)
	router.POST("/check_username", check_username_Handler)
	//private
	router.POST("/post_level", post_level_Handler)           //THERE IS NO AUTH, VERY UNSAFE 
	router.GET("/get_levels", get_levels_Handler)           //THERE IS NO AUTH, VERY UNSAFE
	router.POST("/player_winner_db", player_winner_db_Handler)     //THERE IS NO AUTH, VERY UNSAFE        AT LEAST ADD RANDOM CHARACTERS TO ROUTE!!!
	router.POST("/match_end", match_end_Handler)            //THERE IS NO AUTH, VERY UNSAFE
	router.POST("/online_push", online_push_Handler)          //THERE IS NO AUTH, VERY UNSAFE
	//logout
	router.GET("/logout", LogOutHandler)
	router.RunTLS("yourip:8080", "/home/fullchain.pem", "/home/privkey.pem")
}
