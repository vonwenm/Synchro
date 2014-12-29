package synchro

import (
		"sync"
		"strings"
		"net/url"
		"crypto/ecdsa"
		"net/http"
		"crypto/rsa"
		"os"
		"io"
		"fmt"
		"github.com/golangdaddy/go-tools-essential"
		"code.google.com/p/go.net/websocket"
		"reflect"
		)

var user_index map[string]*OBJ
	
type temp_secrets struct {
	ecdsa_secret string
	rsa_secret string
	revoke_secret string
}

type Storage struct {
	Local bool
	Data map[string]string
	Objects map[string]*OBJ
	Pointers map[string]*Signature
	Index  map[string]*Index
	backup_channel chan *OBJ
	sync.RWMutex
}

func (s *Storage) New() *Storage {
	s = &Storage{}
	s.Local = true
	s.Data = make(map[string]string)
	s.Objects = make(map[string]*OBJ)
	s.Pointers = make(map[string]*Signature)
	s.Index = make(map[string]*Index)
	s.backup_channel = make(chan *OBJ, 999)
	return s
}

type Infrastructure struct {
	root_secret string
	RootAuthority *OBJ
	Storage *Storage
	Deployment *Deployment
	Templates map[string]*Template
	API *APIController
	Logger *MultiLogger
	REQUESTS chan *Request
	GLOBALS map[string]string
	SENDMAIL chan url.Values
	SSLCertPath string
	SSLKeyPath string
	sessions map[string]*NetSession
	request_cache map[string]bool
	private_ecdsa *ecdsa.PrivateKey
	private_rsa *rsa.PrivateKey
	loaded bool
	channel chan string
	logs chan string
	elogs chan string
	sync.RWMutex
}

func (i *Infrastructure) BroadcastObject(id string) bool { o := i.ReadObject(id); if o != nil { return o.Send_json(nil, i.sessions) }; return false }
func (i *Infrastructure) Private_ecdsa() *ecdsa.PrivateKey { return i.private_ecdsa }
func (i *Infrastructure) Private_rsa() *rsa.PrivateKey { return i.private_rsa }
func (i *Infrastructure) Error(e string) { i.elogs<-e }
func (i *Infrastructure) Errors() chan string { return i.elogs }
func (i *Infrastructure) Log(e string) { i.logs<-e }
func (i *Infrastructure) Logs() chan string { return i.logs }
func (i *Infrastructure) RegisterSession(sesh *NetSession) { i.sessions[sesh.user.PublicName()] = sesh; i.logs<-"REGISTERED NEW SESSION" }
func (i *Infrastructure) Sessions() map[string]*NetSession { return i.sessions }

func BasicInfrastructure(website_protocol, website_host string, logger *MultiLogger) *Infrastructure {
	i := &Infrastructure{}
	i.StartLogs(logger)
	i.Deployment = &Deployment{}
	i.Deployment.Host = website_host
	i.Deployment.Protocol = website_protocol
	i.SSLCertPath = "./ssl/"+website_host+"/ssl.cert"
	i.SSLKeyPath = "./ssl/"+website_host+"/ssl.key"
	return i
}

func (i *Infrastructure) StartLogs(logger *MultiLogger) {
	i.Logger = logger
	i.logs = logger.NewLog(":")
	i.elogs = logger.NewLog("!!!")
}

func (i *Infrastructure) UserMap(username string) (bool, *OBJ) {
	if !strings.Contains(username, "@") { username += "@"+i.Deployment.Host }
	i.logs<-"SEARCHING FOR USER IN USERMAP: "+username
	if user_index == nil { user_index = make(map[string]*OBJ) }
	if user_index[username] != nil { return true, user_index[username] }
	ok, _, users := i.GetIndex("/system/users")
	if ok {
		for user_id, _ := range users.Objects {
			user := i.ReadObject(user_id); if user == nil { continue }
			if user.Type() == "USER" && user.Host() == i.Deployment.Host { if user.PublicName() == username { user_index[username] = user; return true, user } }
		}
	}
	i.logs<-"*Infrastructure: USER "+username+" NOT IN USERMAP"
	return false, nil
}

func (i *Infrastructure) Modal(name string) *Modal {
	modal := i.Deployment.Modals[name]
	if modal != nil { return modal }
	tools.Quit_slow(i.logs, "*Infrastructure: MISSING MODAL REFERENCE")
	return nil
}

func (i *Infrastructure) GenerateCertificate(secret_key string) map[string]interface{} {
	subkey := NewSubKeys(secret_key)
	for {
		ok := false
		m := make(map[string]interface{})
		m["ID"] = tools.ID_strong()
		if (i.RootAuthority != nil) { m["ROOT"] = i.RootAuthority.ID() }
		ok, m["ECDSA"] = tools.Generate_ecdsa(i.logs, subkey.ecdsa_secret); if !ok { break }
		ok, m["RSA"] = tools.Generate_openssl(i.logs, i.Deployment.RSAKeyLength, subkey.rsa_secret); if !ok { break }
		m["REVOKE"] = tools.SHA_256(subkey.revoke_secret)
		return m
	}
	tools.Quit_slow(i.logs, "SYNCHRO: PANIC"); return nil
}

func (i *Infrastructure) NewUser(username, secret_key string, details map[string]string) (bool, *OBJ) {
	i.Log("CREATING NEW USER "+username)
	if username == "guest" || details == nil {
		data := make(map[string]interface{})
		data["USERNAME"] = username
		return i.NewObject("USER", data)
	} else {
		data := i.GenerateCertificate(secret_key)
		data["USERNAME"] = username
		data["DETAILS"] = details
		return i.NewObject("USER", data)
	}
	i.Error("FAILED TO CREATE NEW USER"); return false, nil
}

func (i *Infrastructure) NewStringObject(object_type string, data map[string]string) (bool, *OBJ) {
	m := make(map[string]interface{})
	for k, val := range data { m[k] = val }
	return i.NewObject(object_type, m)
}

func (i *Infrastructure) NewObject(object_type string, data map[string]interface{}) (bool, *OBJ) {
	if len(object_type) == 0 { object_type = "DEFAULT" } else { object_type = strings.ToUpper(object_type) }
	if data == nil { data = make(map[string]interface{}) }
	o := &OBJ{}
	o.i = i
	o.Data = data
	o.Data["_TYPE"] = object_type
	o.Data["_HOST"] = i.Deployment.Host
	o.Data["_TIME"] = tools.Time_map()
	digested := o.Digest()
	if digested { return true, o }
	i.logs<-"NEWOBJECT: FAILED TO CREATE NEW TYPE: "+object_type
	return false, nil
}

func (i *Infrastructure) NewUpload(res http.ResponseWriter, r *http.Request) {
	ok, user := SessionKeyToUser(r.FormValue("sessionkey")); if !ok { i.logs<-"FAILED TO AUTH USER FOR UPLOAD"; return }
	err := r.ParseMultipartForm(100000); if err != nil { i.logs<-"FAILED TO PARSE MULTIPART FORM"; return }
	m := r.MultipartForm
	files := m.File["payload"]
	for x, _ := range files {
		file, err := files[x].Open()
		if file != nil { defer file.Close() }
		if err != nil { i.logs<-"FAILED TO HANDLE UPLOADED FILE"; break }
		file_name := files[x].Filename
		ft := strings.Split(file_name, ".")
		if len(ft) != 2 { i.logs<-"FAILED TO GET VALID TYPE FROM FILENAME 1"; break }
		if len(ft[1]) < 2 || len(ft[1]) > 4 { i.logs<-"FAILED TO GET VALID TYPE FROM FILENAME 2"; break }
		ok, file_type := tools.Parse_safe(i.logs, tools.Lowercase(ft[1])); if !ok { i.logs<-"FAILED TO GET VALID TYPE FROM FILENAME 3"; break }
		full_path := i.Deployment.UploadsPath+user.User()+"/uploads/"+file_type+"/"
		tools.File_makepath(i.logs, full_path)
		full_path += tools.SHA_1(file_name)+".upload"
		dst, err := os.Create(full_path)
		defer dst.Close(); if err != nil { i.logs<-"FAILED TO CREATE LOCAL FILE"; break }
		_, err = io.Copy(dst, file); if err != nil { i.logs<-"FAILED TO HANDLE UPLOADED FILE"; break }
		ok, file_bytes := tools.File_read_bytes(i.logs, full_path); if !ok { i.logs<-"FAILED TO DIGEST VALID FILE"; break}
		hashed, _ := tools.SHA(1, 0, "", file_bytes)
		// create storage object
		icon_url := i.Deployment.Protocol+i.Deployment.Host+"/uploads/"+user.User()+"/"+tools.Lowercase(file_type)+"/"+tools.SHA_1(file_name)
		if file_type != "JPG" && file_type != "JPEG" && file_type != "PNG" && file_type != "GIF" { icon_url = "/theme/image/document.png" }  
		m := make(map[string]interface{})
		m["NAME"] = file_name
		m["ICON"] = icon_url
		m["SHA1"] = hashed
		ok, o := i.NewObject("UPLOAD", m); if !ok { break }
		o.Send_json([]*OBJ{user}, nil)
	}
	i.logs<-"NEW UPLOAD REQUEST FAILED"
}

func (i *Infrastructure) UnlockCertificate(user *OBJ, key_type, secret_key string) (bool, *ecdsa.PrivateKey, *rsa.PrivateKey) {
	if user == nil { tools.Quit_slow(i.logs, "*Infrastructure: NIL USER IN UNLOCK CERTIFICATE") }
	key_type = strings.ToUpper(key_type)
	if user.temp == nil {
		user.Lock()
			user.temp = make(map[string]interface{})
		user.Unlock()
	}
	encrypted_key := ""
	user.RLock()
		switch v := user.Data[key_type].(type) {
			case map[string]interface{}: ok, ks := interface_to_map(i.logs, user.Data[key_type]); if ok { e, ok := ks["EncryptedPrivateKey"].(string); if ok { encrypted_key = e } }
			case map[string]string: ks, ok := user.Data[key_type].(map[string]string); if ok { encrypted_key = ks["EncryptedPrivateKey"] }
			default: fmt.Println(v)
		}
	user.RUnlock()
	if len(encrypted_key) == 0 { tools.Quit_slow(i.logs, "*Infrastructure: KEYSTORE FAIL, "+key_type+" INTERFACE IS "+reflect.TypeOf(user.Data[key_type]).String()) }
	keys := NewSubKeys(secret_key)
	switch key_type {
		case "ECDSA":
			if user.temp[key_type] != nil { key, ok := user.temp[key_type].(*ecdsa.PrivateKey); if ok { return true, key, nil }; break }
			ok, private_key, _ := tools.RecoverKey(i.logs, key_type, encrypted_key, keys.ecdsa_secret)			
			if ok { if user == i.RootAuthority { user.temp[key_type] = private_key }; return true, private_key, nil }
		case "RSA":
			if user.temp[key_type] != nil { key, ok := user.temp[key_type].(*rsa.PrivateKey); if ok { return true, nil, key }; break }
			ok, _, private_key := tools.RecoverKey(i.logs, key_type, encrypted_key, keys.rsa_secret)
			if ok { if user == i.RootAuthority { user.temp[key_type] = private_key }; return true, nil, private_key }
		default: tools.Quit_slow(i.logs, "*Infrastructure: INCORRECT KEY IDENTIFIER "+key_type)
	}
	i.logs<-"*Infrastructure: FAILED TO UNLOCK CERTIFICATE "+key_type
	return false, nil, nil
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewSubKeys(secret_key string) *temp_secrets {
	secrets := &temp_secrets{}
	for x := 0; x < 10; x++ {
		_, hashed_bytes := tools.Scrypt_512(make(chan string), secret_key)
		secret_key, _ = tools.SHA(3, 128, "", hashed_bytes)
	}
	secrets.ecdsa_secret, _ = tools.SHA(3, 128, secret_key[0:64], nil)
	secrets.rsa_secret, _ = tools.SHA(3, 128, secret_key[64:128], nil)
	secrets.revoke_secret, _ = tools.SHA(3, 128, secret_key[32:64]+secret_key[96:128], nil)
	secrets.revoke_secret = tools.SHA_3_512(secrets.revoke_secret)
	return secrets
}

func (i *Infrastructure) Socket_open(route string, port int, handlerfunc func(*websocket.Conn)) {
	port_string := ":"+tools.IntToString(port)
	if string(route[0]) != "/" { route = "/"+route }
	i.logs<-"SOCKET/OPEN: "+port_string+route
	http.Handle(route, websocket.Handler(handlerfunc))
	go func() {
		if i.Deployment.Protocol == "https://" {
			err := http.ListenAndServeTLS(port_string, i.SSLCertPath, i.SSLKeyPath, nil)
			if err != nil { i.logs<-"TOOLS/SOCKET/OPEN: "+err.Error() }
		} else {
			err := http.ListenAndServe(port_string, nil)
			if err != nil { i.logs<-"TOOLS/SOCKET/OPEN: "+err.Error() }
		}
		i.logs<-"TOOLS/SOCKET/OPEN: CLOSED SOCKET "+port_string+route
	}()
}

/////////////////////////////////////////////////////
