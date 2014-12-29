package synchro

import (
		"github.com/golangdaddy/go-tools-essential"
		"net/url"
		"net/http"
		"io/ioutil"
		"strings"
		)
		
func (i *Infrastructure) SendEmail(recipient, email_id string) bool {
	email := i.Deployment.Emails[email_id]
	if email != nil {
		ok, body := tools.URL_get(i.logs, i.Deployment.Core["paths"]["all_static"]+email.BodyPath)
		if ok { if i.SendMail(email.Sender, recipient, email.Subject, body) { i.logs<-"**** SENT DEPLOYMENT EMAIL "+email_id+" TO "+recipient; return true } }
	}
	i.logs<-"SENDMAIL: FAILED TO FIND/SEND DEPLOYMENT EMAIL"
	return false
}
		
func (i *Infrastructure) SendMail(from, to, subject, text string) bool {
	if i.SENDMAIL == nil {
		i.SENDMAIL = make(chan url.Values)
		go func() {
			for {
				values := <- i.SENDMAIL
				client := &http.Client{}
				request, _ := http.NewRequest("POST", "https://api.mailgun.net/v2/"+i.Deployment.MailerDomain+"/messages", strings.NewReader(values.Encode()))
				request.Header.Set("content-type", "application/x-www-form-urlencoded")
				request.SetBasicAuth("api", i.Deployment.MailerAPI)
				response, e1 := client.Do(request)
				if e1 != nil { i.Log("SENDMAIL: FAILED "+e1.Error()); continue }
				defer response.Body.Close()
				if response.StatusCode != 200 { i.Log("SENDMAIL: ERROR STATUS "+response.Status); continue }
				body, err := ioutil.ReadAll(response.Body)
				if err == nil {
					i.Log("SENDMAIL: SENT EMAIL")
					i.Log(string(body))
				}
				// prevent accidental bulk requests
				tools.Sleep(1)
			}
		}()
	}
	if tools.Parse_email(i.Errors(), to) && tools.Parse_email(i.Errors(), from) {
		// prevent accidental bulk data sending
		if len(subject) < 199 && len(text) < 1999 {
			values := make(url.Values)
			values.Set("from", from)
			values.Set("to", to)
			values.Set("subject", subject)
			values.Set("text", text)
			i.SENDMAIL <- values
			return true
		} else { i.Error("SENDMAIL: EMAIL CONTENT LENGTH INVALID") }
	} else { i.Error("SENDMAIL: ONE OR MORE EMAIL ADDRESSES INVALID") }
	i.Error("SENDMAIL: FAILED EMAIL FROM "+from+" TO "+to); return false
}

func send_registration_email_to(user *OBJ) bool {	
	d := user.i.Deployment
	if len(d.MailerAPI) == 0 { return true }
	username := user.User()
	for {
		key_id := tools.ID_strong()
		ok, email_address := user.Details("EMAIL"); if !ok { break }
		email_text := "Thanks for signing-up "+username+", please click the following link to verify your email address: \n\n "+d.Protocol+d.Host+"/verify/"+key_id
		if !user.i.SendMail("no-reply@"+d.Host, email_address, "Welcome to "+d.DisplayID+"!", email_text) { break }
		new_key := make(map[string]interface{})
		new_key["CODE"] = tools.SHA_256(key_id)
		new_key["EMAIL"] = email_address
		new_key["USER"] = username
		ok, key := user.i.NewObject("EMAILVERIFICATION", new_key); if !ok { break }
		if !key.CloneTo("/email/validationkeys") { break }
		user.i.BroadcastObject(key.ID())
		return true
	}
	user.i.Error("SENDMAIL: REGISTRATION EMAIL FAILED"); return false
}

func Redirect(path string, res http.ResponseWriter, r *http.Request) { http.Redirect(res, r, path, http.StatusFound) }

func (i *Infrastructure) VerifyEmailAddress(res http.ResponseWriter, r *http.Request) {
	validation_path := "/email/validationkeys"
	i.logs<-"<<<< RECEIVED A NEW VALIDATION REQUEST"
	key_id := tools.SHA_256(r.URL.Query().Get(":one"))
	if tools.Digest_valid(i.logs, key_id) {
		for id, _ := range i.IndexObjects(validation_path) {
			validation_object := i.ReadObject(id); if validation_object == nil { continue }
			
			// check if code matches
			ok, code := validation_object.StrData("CODE"); if !ok { continue }
			if code != key_id { continue }
			i.logs<-"**** FOUND EMAIL VALIDATION CODE"
			
			for id, _ := range validation_object.Data { i.logs<-"SCANNING: "+id }
			
			// correct match, validate other data
			ok, email_address := validation_object.StrData("EMAIL"); if !ok { break }
			ok, username := validation_object.StrData("USER"); if !ok { break }
			ok, user := i.UserMap(username); if !ok { break }
			if !validation_object.CloneTo(user.ID()) { break }
			if !i.DeleteFromIndex(validation_path, id) { tools.Quit_slow(i.logs, "FAILED TO DELETE OLD OBJECT") }
			CONTROLLER.UPDATE_INDEX <- true
			i.logs<-"**** VALIDATED "+email_address+" FOR USER "+username
			go i.SendEmail(email_address, "email_welcome")
			Redirect("/?alert="+tools.Encode_base64([]byte("registrationcomplete")), res, r)
			return
		}
	}
	i.logs<-"!!!! VALIDATION REQUEST FAILED"
	Redirect("/?alert="+tools.Encode_base64([]byte("emailverification")), res, r)
}

