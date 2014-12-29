package synchro

import (
		"github.com/golangdaddy/go-tools-essential"
		"github.com/golangdaddy/go-multi-logger"
		"github.com/golangdaddy/go-zencode"
		"code.google.com/p/go.net/websocket"
		"github.com/bmizerany/pat"
		"net/http"
		"strings"
		"fmt"
		)

func (i *Infrastructure) Start(deploy_package string, logger *MultiLogger) *Infrastructure {
	i = &Infrastructure{}
	i.GLOBALS = make(map[string]string)
	i.Storage = (&Storage{}).New()
	i.StartLogs(logger)
	
	go i.backup_handler()
	
	i.LoadPackage(deploy_package)
	
	go func() {
		if i.UpdateCoreDB() {
			mux := pat.New()
			mux.Get("/"+i.Deployment.AdminRoute, http.HandlerFunc(i.admin_login))
			i.Socket_open("admin", 96, i.admin_socket)
			if i.Deployment.Protocol == "https://" {
				tools.Quit_slow(i.logs, (http.ListenAndServeTLS(":"+i.Deployment.AdminPort, i.SSLCertPath, i.SSLKeyPath, mux)).Error())
			} else {
				tools.Quit_slow(i.logs, (http.ListenAndServe(":"+i.Deployment.AdminPort, mux)).Error())
			}
		}
		tools.Quit_slow(i.logs, "FAILED CORE DATABASE IMPORT !!!")
	}()
	
	i.Log("...Waiting for SuperUser Authentication")
	for i.RootAuthority == nil { tools.Sleep(1); }
	for {
		i.Log("EXTRACTING ROOT SECRET...")
		ok, ecdsa_private_key, _ := i.UnlockCertificate(i.RootAuthority, "ECDSA", ""); if !ok { break }
		ok, _, rsa_private_key := i.UnlockCertificate(i.RootAuthority, "RSA", ""); if !ok { break }
		ok, b := tools.Encode_gob(i.logs, ecdsa_private_key); if !ok { break }
		ok, c := tools.Encode_gob(i.logs, rsa_private_key); if !ok { break }
		i.root_secret = tools.SHA_256(string(b)+string(c))
		
		if !tools.File_makepath(i.logs, strings.Join(strings.Split(deploy_package, "/")[0:len(strings.Split(deploy_package, "/"))-2], "/")) { break }
		i.logs<-"CREATING NEW PUBLIC KEY INFRASTRUCTURE"
		i.API = (&APIController{}).New(i)
		i.REQUESTS = make(chan *Request, 999)
		i.sessions = make(map[string]*NetSession)
		i.request_cache = make(map[string]bool)
		i.logs<-"NEW INFRASTRUCTURE CREATED OK"
		return i
	}
	tools.Quit_slow(i.logs, "FAILED TO INITIALIZE APPLICATION...")
	return nil
}

func (i *Infrastructure) UpdateCoreDB() bool {
	i.logs<-"CORE: UPDATING DATA..."
	if i.Storage.Data == nil { i.Storage.Data = make(map[string]string) }
	ok, list := tools.File_dir_list(i.logs, "./USERS/"); if !ok { return false }
	for _, file_path := range list {
		ok, s := tools.File_read_string(i.logs, "./USERS/"+file_path)
		if ok {
			i.Storage.Data[file_path] = s
			i.logs<-"CORE: "+file_path
		}
	}
	return true
}

func (i *Infrastructure) admin_login(res http.ResponseWriter, r *http.Request) {
	err := "404"
	if len(r.FormValue("user")) < 32 {
		if i.Deployment.AdminUsers[r.FormValue("user")] {
			ok, page := tools.Decode_base64(mlog.DummyChannel(), i.Deployment.Core["files"]["admin_login"])
			if ok {
				websocket_url := i.Deployment.Host+":96/admin"
				if i.Deployment.Protocol == "https://" {
					websocket_url = "wss://"+websocket_url 
				} else {
					websocket_url = "ws://"+websocket_url 
				}
				output := strings.Replace(string(page), "XXXHOSTPATHXXX", websocket_url, -1)
				output = strings.Replace(output, "XXXSTATICPATHXXX", i.Deployment.Core["paths"]["all_static"], -1)
				output = strings.Replace(output, "XXXDEVSTATICPATHXXX", i.Deployment.Core["paths"]["dev_static"], -1)
				fmt.Fprintf(res, "%v", output)
				return
			}
		}
	}
	fmt.Fprintf(res, "%v", err)
	tools.Quit_slow(i.logs, "FAILED TO SERVE ADMIN LOGIN !!!")
}

func (i *Infrastructure) admin_socket(ws *websocket.Conn) {
	if i.RootAuthority != nil { i.logs<-"!!!! PROGRAM HAS ALREADY BEEN STARTED"; return }
	i.Log("<<<< RECEIVED NEW WEBSOCKET CONNECTION")
	i.UpdateCoreDB()
	i.RLock()
		for _, s := range i.Storage.Data { err := websocket.Message.Send(ws, s); if err != nil { tools.Quit_slow(i.logs, "ADMIN: ERROR "+err.Error()) } }
	i.RUnlock()
	for {
			m := make(map[string]string)
			if ws == nil { break }
			err := websocket.JSON.Receive(ws, &m); if err != nil { continue }
			i.logs<-"**** NEW MESSAGE RECEIVED"
			msg := m["msg"]
			user_id := m["id"]
			user_secret := m["secret"]
			switch msg {
				case "login":
					i.logs<-"*Infrastructure: TARGETING SUPER USER "+user_id
					super_user := i.ReadObject(user_id)
					if super_user != nil {
						ok, object_type := super_user.StrData("_TYPE")
						if ok && object_type == "USER" {
							ok, _, _ := i.UnlockCertificate(super_user, "RSA", user_secret)
							if ok {
								ok, _, _ := i.UnlockCertificate(super_user, "ECDSA", user_secret)
								if ok {
									index_path := i.Deployment.Core["paths"]["index_db"]+super_user.KeyID("ECDSA")+"/.json"
									i.logs<-"**** AUTHENTICATING SUPER USER..."
									i.logs<-"**** DOWNLOADING FROM "+index_path
									ok, b := tools.URL_get_bytes(i.logs, index_path)
									if ok {
										if tools.Decode_json(i.logs, b, &i.Storage.Index) {
											i.logs<-"**** AUTHENTICATED SUPER USER"
											if i.Storage.Index == nil {
												i.logs<-"**** CREATING NEW ROOT INDEX"
												i.Storage.Index = make(map[string]*Index)
											} else {
												i.logs<-"**** DOWNLOADED ROOT INDEX OK"
											}
											i.RootAuthority = super_user
											continue
										}
									}
								}
							}
						}
					}
					i.logs<-"**** FAILED SUPER USER AUTH"; continue
				case "newuser":
					i.logs<-"*Infrastructure: CREATING SUPER USER"
					details := make(map[string]string)
					ok, user := i.NewUser("root", user_secret, details); if !ok { break }
					if !tools.File_write_string(i.logs, "./USERS/"+user.ID(), zencode.Encode(user.Data)) { break }
					i.logs<-"*Infrastructure: CREATED NEW SUPER USER"
					continue
			}
			i.logs<-"*Infrastructure: FAILED TO MAKE NEW SUPER USER";
	}
	i.logs<-"**** CLOSED CONNECTION TO CLIENT"
}