package synchro
	
import (
		"crypto/ecdsa"
		"crypto/rsa"
		"crypto/rand"
		"crypto/x509"
		"net/http"
		"strings"
		"sync"
		"github.com/golangdaddy/go-tools-essential"
		"code.google.com/p/go.net/websocket"
		)

var CONTROLLER *APIController
var GUEST_USER *OBJ

type Request struct {
	ID string
	Username string
	Action string
	Modal string
	Tokens map[string]string
	Private bool
		object []byte
		user *OBJ
		input map[string]string
		in *http.Request
		out *http.ResponseWriter
		temp_keys map[string]string
		rsa_key *rsa.PrivateKey
		aes_key []byte
		aes_iv []byte
		channel chan bool
		i *Infrastructure
}

func (R *Request) RemoteIP() string { 
        hdr := R.in.Header 
        hdrRealIp := hdr.Get("X-Real-Ip") 
        hdrForwardedFor := hdr.Get("X-Forwarded-For") 
        if hdrRealIp == "" && hdrForwardedFor == "" {
			index_pos := strings.LastIndex(R.in.RemoteAddr, ":") 
			if index_pos == -1 { return R.in.RemoteAddr }
			return R.in.RemoteAddr[:index_pos]
		} 
        if hdrForwardedFor != "" { 
                // X-Forwarded-For is potentially a list of addresses separated with "," 
                parts := strings.Split(hdrForwardedFor, ",") 
                for i, p := range parts { parts[i] = strings.TrimSpace(p) } 
                // TODO: should return first non-local address 
                return parts[0] 
        } 
        return hdrRealIp 
} 

func (R *Request) ECDSAkey() (bool, *ecdsa.PrivateKey) {
	ok, plain_bytes := R.PullAndDecrypt("KEYS", "ECDSA"); if !ok { return false, nil }
	private_key, err := x509.ParseECPrivateKey(plain_bytes)
	if err != nil { R.Error("*Request: "+err.Error()); return false, nil }
	return true, private_key
}

func (R *Request) Create() (bool, *OBJ) {
	for {
		ok, data := R.Object(); if !ok { R.Error("*OBJ: FAILED TO GET JSON PAYLOAD"); break }
		ok, o := R.i.NewObject(R.input["type"], data); if !ok { break }
		if !o.CloneTo(R.input["taxonomy"]) { break }
		return true, o
	}
	R.Error("FAILED TO CREATE NEW OBJECT ("+R.Input("taxonomy")+")"); return false, nil
}

func (R *Request) Object() (bool, map[string]interface{}) {
	m := make(map[string]interface{})
	if tools.Decode_json(R.Errors(), R.object, &m) { return true, m }
	return false, nil
}

func (R *Request) System() *Infrastructure { return R.i }
func (R *Request) Error(e string) { CONTROLLER.channel<-e }
func (R *Request) Errors() chan string { return CONTROLLER.channel }
func (R *Request) User() *OBJ { return R.user }
func (R *Request) CheckOrigin() string { stringhash, _ := tools.SHA(1, 0, strings.Split(R.in.RemoteAddr, ":")[0]+R.user.PublicName(), nil); return stringhash }
func (R *Request) Input(i string) string { return R.input[i] }
func (R *Request) Inputs() map[string]string { return R.input }

func (R *Request) PullAndDecrypt(x, y string) (bool,[]byte) {
	if len(R.temp_keys["DEEPKEY"]) == 0 { R.Error("PULL&DECRYPT: DEEPKEY INVALID "+tools.IntToString(len(R.temp_keys["DEEPKEY"]))); return false, nil }
	for {
		encoded_key, ok := (R.user.Session()).PullData(x, y).(string); if !ok { R.Error("PULL&DECRYPT: PULL DATA FAILED"); break }
		ok, decoded_key := tools.Decode_base64(R.Errors(), encoded_key); if !ok { break }
		ok, plain_bytes := tools.Crypt_aes(R.Errors(), false, R.temp_keys["DEEPKEY"], decoded_key); if !ok { break }
		return ok, plain_bytes
	}
	R.Error("PULL AND DECRYPT FAILED")
	return false, nil
}

func (R *Request) DecryptRSA(o *OBJ) []byte {
	for {
		p, ok := o.Data["P"].(string); if !ok { R.Error("CRYPTOAPI TYPE ASSERTION ERROR"); break } 
		c, ok := o.Data["C"].(string); if !ok { R.Error("CRYPTOAPI TYPE ASSERTION ERROR"); break }
		ok, plain_bytes := R.PullAndDecrypt("KEYS", "RSA"); if !ok { break }
		private_key, err := x509.ParsePKCS1PrivateKey(plain_bytes); if err != nil { R.Error("CRYPTOAPI/REQUEST/DECRYPT: "+err.Error()); break }
		err = private_key.Validate(); if err != nil { R.Error("CRYPTOAPI/DECRYPTRSA: "+err.Error()); break }
		_, _, plain_bytes = DecryptRSA(R, p, c, private_key)
		return plain_bytes
	}
	return nil
}

type APIController struct {
	i *Infrastructure
	UPDATE_INDEX chan bool
	guest_privatekey *rsa.PrivateKey
	guest_publickey string
	request_cache map[string]bool
	api_key_index map[string]*OBJ
	email_index map[string]bool
	session_key_index map[string]*OBJ
	channel chan string
	sync.RWMutex
}

func SessionKeyToUser(session_key string) (bool, *OBJ) {
	user := CONTROLLER.session_key_index[session_key]
	if user == nil { return false, nil}; return true, user
}

func (api *APIController) New(i *Infrastructure) *APIController {
	if CONTROLLER != nil { tools.Quit_slow(CONTROLLER.i.Errors(), "API CONTROLLER WAS RE-INSTANTIATED") }
	api = &APIController{}
	api.i = i
	api.request_cache = make(map[string]bool)
	api.UPDATE_INDEX = make(chan bool, 99)
	api.email_index = make(map[string]bool)
	api.api_key_index = make(map[string]*OBJ)
	api.session_key_index = make(map[string]*OBJ)
	api.channel = i.Logger.NewLog("API:>")
	ok := false
	key_seed := tools.Entropy64()
	ok, new_keystore := tools.Generate_openssl(api.channel, 1024, key_seed); if !ok { tools.Quit_slow(api.channel, "CANT GEN GUEST RSA KEY") }
	ok, _, api.guest_privatekey = tools.RecoverKey(api.channel, new_keystore["ID"], new_keystore["EncryptedPrivateKey"], key_seed); if !ok { tools.Quit_slow(api.channel, "CANT RECOVER GUEST RSA KEY") }
	api.guest_publickey = new_keystore["EncodedPublicKey"]; if !ok { tools.Quit_slow(api.channel, "CANT TYPE ASSERT ENCODED KEY") }
	CONTROLLER = api
	
	go func() {
		for {
				CONTROLLER.i.Log("<<<<-----------------------------UPDATE INDEX")
				m := make(map[string]bool)
				for user_id, _ := range CONTROLLER.i.IndexObjects(CONTROLLER.i.Deployment.UserPath) {
					user := CONTROLLER.i.ReadObject(user_id)
					username := user.User()
					if username == "root" || username == "guest" { continue }
					tools.Sleep(1)
					if user != nil {
						ok, email := user.Email(); if ok { m[local_email_id(email)] = true }
					}
				}
				CONTROLLER.Lock()
					CONTROLLER.email_index = m
				CONTROLLER.Unlock()
				<- CONTROLLER.UPDATE_INDEX
		}
	}()
	
	ok, _ = i.NewUser("guest", tools.ID_strong(), nil); if !ok { tools.Quit_slow(api.channel, "FAILED TO CREATE GUEST USER") }
	// serve websocket handler
	i.Socket_open("visitor", 93, WS_Request)
	return api
}

func local_email_id(s string) string { return tools.SHA_1(CONTROLLER.i.Deployment.ID+s) }

func (api *APIController) do_auth(session_key, username string) (bool, *OBJ) {
	for {
		user := api.session_key_index[session_key]; if user == nil { break }
		if username != user.User() || username == "guest" { api.i.Error("USERNAME IS BROKEN / INVALID"); break }
		ok, new_user := api.i.UserMap(username)
		if !ok || user != new_user { break }
		return true, user
	}
	api.i.Error("DO_AUTH FAILED TO RESOLVE API KEY TO USER"); return false, nil
}

func form_validate(form_id string, R *Request) (bool, string, string, map[string]string) {
	fields := R.i.Deployment.FormDetails[form_id]; if fields == nil { tools.Quit_slow(R.Errors(), "REGISTER: FORM DETAILS ARE BROKEN") }
	new_fields := make(map[string]string)
	for detail, length := range fields {
		detail = strings.ToUpper(detail)
		R.Error(tools.IntToString(len(R.input))+" MAX, PARSING USER DETAIL: "+detail)
		input := R.input[strings.ToLower(detail)]
		if len(input) == 0 { R.Error("REGISTER1: INVALID FIELD LENGTH MIN "+detail); return false, "", "", nil }
		switch detail {
			case "USERNAME":
							ok := false; ok, input = tools.Parse_safe(R.Errors(), input); if !ok { break }
							user_exists, _ :=  R.i.UserMap(input)
							if user_exists {
								R.Error("*Request: USERNAME ("+input+") ALREADY EXISTS")
								R.Modal = "usernameexists"
								return false, "", "", nil
							}
			break
			case "PASSWORD":
							if !tools.Digest_valid(R.Errors(), input) {
								R.Error("DIGEST EXPECTED FOR AUTHORIZATION")
								R.Modal = "invalidpassword"
								return false, "", "", nil
							}
			break
			case "EMAIL":	
							email := tools.Parse_sanitize(input)
							if CONTROLLER.email_index[local_email_id(email)] {
								R.Modal = "existingemail"
								return false, "", "", nil
							}
							if !tools.Parse_email(R.Errors(), email) {
								R.Modal = "invalidemail"
								return false, "", "", nil
							}
			break
			default:		input = tools.Parse_sanitize(input)
		}
		fail := false
		if len(input) > length { R.Error("REGISTER: INVALID FIELD LENGTH MAX "+detail); fail = true }
		if len(input) == 0 { R.Error("REGISTER2: INVALID FIELD LENGTH MIN "+detail); fail = true }
		if fail {
			R.Modal = "adminsentemail"
			return false, "", "", nil
		}
		new_fields[detail] = input
	}
	username := new_fields["USERNAME"]
	password := new_fields["PASSWORD"]
	delete(new_fields, "USERNAME")
	delete(new_fields, "PASSWORD")
	return true, username, password, new_fields
}

func Register(R* Request) {
	for {
		ok, username, secret_key, details := form_validate("REGISTER", R); if !ok { break }
		ok, ip_hash := tools.Scrypt_128(R.Errors(), R.RemoteIP()); if !ok { break }
		details["REMOTEIP"], _ = tools.SHA(1, 0, "", ip_hash)
		ok, o := R.i.NewUser(username, secret_key, details); if !ok { R.Error("*Request: FAILED TO CREATE NEW USER"); break }
		if !send_registration_email_to(o) { break }
		if !o.CloneTo(R.i.Deployment.UserPath) { break }
		R.i.BroadcastObject(o.ID())
		R.Modal = "checkemail"
		R.Error("REGISTRATION COMPLETE"); return
	}
	R.Error("REGISTRATION FAILED")
}

func Login(R *Request) {
	for {
		ok, username := tools.Parse_safe(R.Errors(), R.input["username"]); if !ok { break }
		ok, user := R.i.UserMap(username); if !ok { R.Error("LOGIN: FAILED TO FIND USER FOR USERNAME"); break };
		secret_key := R.input["password"]; if !tools.Digest_valid(R.Errors(), secret_key) { R.Errors()<-"LOGIN: DIGEST EXPECTED FOR AUTHORIZATION"; break }

		// check user email verification status
		
		verified, _:= user.Email() 
		if !verified { R.Modal = "emailverification"; return }
		
		// unlock keys ready for local encryption
		
		ok, _, rsa_key := R.i.UnlockCertificate(user, "RSA", secret_key); if !ok { break }
		ok, ecdsa_key, _ := R.i.UnlockCertificate(user, "ECDSA", secret_key); if !ok { break }
		ok, new_digest := tools.Digest_object_quick(R.Errors(), user); if !ok { break }
		r, s, err := ecdsa.Sign(rand.Reader, ecdsa_key, new_digest); if err != nil { R.Errors()<-"LOGIN: FAILED TO SIGN NEW AUTH DIGEST"; break }
		if !ecdsa.Verify(&ecdsa_key.PublicKey, new_digest, r, s) { R.Errors()<-"LOGIN: FAILED TO CREATE VALID AUTH SIG"; break }
		R.user = user
		R.Username = R.user.User()
		R.Tokens = (&NetSession{}).New(R)
		
		// !!! rsa keys

		key_bytes := x509.MarshalPKCS1PrivateKey(rsa_key)
		R.Tokens["PRIVATE_HASH"], _ = tools.SHA(2, 64, "", key_bytes)
		ok, crypt_key := tools.Crypt_aes(R.Errors(), true, R.Tokens["DEEP_KEY"], key_bytes); if !ok { break }
		(R.user.Session()).SetData("keys", "rsa", tools.Encode_base64(crypt_key))

		// !!! ecdsa keys
		coded_key, err := x509.MarshalECPrivateKey(ecdsa_key); if err != nil { R.Error(err.Error()); break }
		ok, crypt_key = tools.Crypt_aes(R.Errors(), true, R.Tokens["DEEP_KEY"], coded_key); if !ok { break }
		(R.user.Session()).SetData("keys", "ecdsa", tools.Encode_base64(crypt_key))

		// register session
		k, iv := (R.user.Session()).SocketKey()
		R.Tokens["SOCKET_KEY"] = tools.Encode_base64(k)
		R.Tokens["SOCKET_IV"] = tools.Encode_base64(iv)
		R.Tokens["PUBLIC_KEY"] = (R.user.Session()).GetPublicKey()
		CONTROLLER.api_key_index[tools.SHA_512(R.Tokens["API_KEY"])] = R.user
		CONTROLLER.session_key_index[R.Tokens["SESSION_KEY"]] = R.user
		R.Error("LOGIN: COMPLETED FOR USER "+R.user.User())
		return
	}
	R.Action = "error"
	R.Modal = "loginfail"
	R.Error("LOGIN: FAILED")
}

func AJAX_Request(res http.ResponseWriter, r *http.Request) {
	CONTROLLER.i.Error("<<<< AJAX REQUEST RECEIVED")
	res.Header().Set("Access-Control-Allow-Origin", CONTROLLER.i.Deployment.URL)
	res.Header().Set("Access-Control-Allow-Methods", "POST")
	ok, R := GuestUser(nil, r); if !ok { return }
	for {
		R.out = &res
		R.ID = r.FormValue("id")
		if CONTROLLER.request_cache[R.ID] { R.Error(" <<<< REQUEST BLOCKED (Goroutine Crash?)"); break }; CONTROLLER.request_cache[R.ID] = true
		if len(R.ID) != 16 || r.Method != "POST" { R.Error(" <<<< WRONG METHOD OR ID LENGTH"); break }
		R.temp_keys["securedata"] = r.FormValue("params")
		R.temp_keys["securekey"] = r.FormValue("keys")
		datalength := len(R.temp_keys["securekey"]); if datalength == 0 || datalength > 3000 { R.Error(" <<<< INPUT KEYS INVALID LENGTH "+tools.IntToString(datalength)); break }
		datalength = len(R.temp_keys["securedata"]); if datalength == 0 || datalength > 9000 { R.Error(" <<<< INPUT PARAMS INVALID LENGTH "+tools.IntToString(datalength)); break }
		if decrypt_request_body(R) { R.i.REQUESTS <- R; <-R.channel; return }
		break
	}
	R.Error("!!! API REQUEST FAILED")
	return
}

func AJAX_Response(R *Request) {
	for {
		ok, reply := tools.Encode_json(R.Errors(), R); if !ok { R.Error("FAILED TO ENCODE JSON RESPONSE"); break }
		ok, reply_bytes := tools.Crypt_aes_cbc(R.Errors(), true, R.aes_key, reply, R.aes_iv); if !ok { R.Error("FAILED TO ENCRYPT JSON RESPONSE"); break }
		tools.Serve(*R.out, tools.Encode_base64(reply_bytes))
		R.Error(" >>>> [ "+R.Username+" COMPLETED API REQUEST "+R.Action+" ] >>>>")
		R.channel<-true; return
	}
	R.Error("FAILED TO SERVE API RESPONSE")
	R.channel<-false
}

func GuestUser(ws *websocket.Conn, r *http.Request)(bool, *Request) {
	R := &Request{}
	R.i = CONTROLLER.i
	// create a copy of guest user
	if GUEST_USER == nil { _, GUEST_USER = R.i.NewUser("guest", tools.Entropy64(), nil) };
	g := *GUEST_USER; R.user = &g; R.Username = R.user.User()
	R.rsa_key = CONTROLLER.guest_privatekey
	R.temp_keys = make(map[string]string)
	R.channel = make(chan bool)
	if ws == nil {
		R.in = r
		R.Tokens = make(map[string]string)
		R.input = make(map[string]string)
		// extract intended username
		R.temp_keys["API_KEY"] = R.in.URL.Query().Get(":user")
		if R.temp_keys["API_KEY"] != "guest" {
			user := CONTROLLER.api_key_index[tools.SHA_512(R.temp_keys["API_KEY"])]
			if user != nil {
				R.Username = user.User()
				for R.Username != "guest" {
					ok, user := R.i.UserMap(R.Username); if !ok { R.Error("FAILED TO FIND "+R.Username+" IN USERMAP"); break }
					s := user.Session(); if s == nil { R.Error("SESSION IS NIL"); break }
					ok, recovered_key := s.GetPrivateKey(R.temp_keys["API_KEY"]); if !ok { break }
					R.rsa_key = recovered_key
					R.Private = true
					return true, R
				}
			} else { R.Error("NO USER FOUND IN API KEY INDEX") }
			R.Error("!!! ABORTED REQUEST AUTHENTICATION"); return false, nil
		}
	} else { R.in = ws.Request() }
	return true, R
}

func WS_Request(ws *websocket.Conn) {
	CONTROLLER.i.Error("<<<< RECEIVED WEBSOCKET CONNECTION")
	ok, R := GuestUser(ws, nil); if !ok { ws.Close(); return }
	for {
		R.temp_keys["API_KEY"] = R.in.FormValue("api")
		ok := tools.Digest_valid(R.Errors(), R.temp_keys["API_KEY"]); if !ok { break }
		u := CONTROLLER.api_key_index[tools.SHA_512(R.temp_keys["API_KEY"])]; if u == nil { R.Error("FAILED TO FIND USER IN API INDEX"); break; }
		ok, R.user = CONTROLLER.i.UserMap(u.PublicName()); if !ok { R.Error("COULDNT FIND USERNAME IN USERMAP"); break }
		session := R.user.Session()
		if session == nil { R.Error("USER SESSION IS NIL"); break }
		if session.Origin != R.CheckOrigin() { R.Error("SESSION ORIGIN SECURITY OVERRIDE!"); break }
		session.NewSocket(ws)
		for user_id, _ := range R.i.IndexObjects(R.i.Deployment.UserPath) { user := R.i.ReadObject(user_id); if user != nil { if !user.Send_json([]*OBJ{R.user}, nil) { R.Error("FAILED TO SYNC USER OBJECT WITH CLIENT") } } }
		for {
			tools.Sleep(60);
			if ws == nil { R.Error("TERMINATED SESSION ON SOCKET CLOSE"); session = nil; break }
			ok = R.user.SendInfo("dummy", nil); if !ok { break }
		}
		CloseSession(R.user);
	}
	R.user.SendGuestInfo(ws, "PUBLIC_RSA", CONTROLLER.guest_publickey)
	<- R.channel
	R.Error("CLOSING WEBSOCKET")
	if ws != nil { ws.Close() }
}

func DecryptRSA(R *Request, p, c string, key *rsa.PrivateKey) ([]byte, []byte, []byte) {
	R.Error("CRYPTOAPI/DECRYPT/RSA")
	for {
		ok, decoded_keys := tools.Decode_hex(R.Errors(), p); if !ok { R.Error("CANT DECODE AES KEY CRYPT HEX"); break }
		AES_key, errz := rsa.DecryptPKCS1v15(rand.Reader, key, decoded_keys); if errz != nil { R.Error(" <<<< "+errz.Error()); R.Error(R.temp_keys["securekey"]); break }
		ok, AES_key_decoded := tools.Decode_base64(R.Errors(), string(AES_key)); if !ok { R.Error("CANT DECODE AES KEY"); R.Error(":"+string(AES_key)); break }
		if !tools.Digest_valid(R.Errors(), string(AES_key_decoded)) { R.Error(" <<<< FAILED! NO VALID AES KEY DECRYPTED"); R.Error(":"+string(AES_key_decoded)); break }
		ok, decoded_params := tools.Decode_hex(R.Errors(), c); if !ok { R.Error("NOT HEX ENCODED"); break }
		ok, aes_key := tools.Decode_hex(R.Errors(), string(AES_key_decoded)); if !ok { R.Error("NOT HEX ENCODED"); break }
		ok, aes_iv := tools.Decode_hex(R.Errors(), string(AES_key_decoded)[0:32]); if !ok { R.Error("NOT HEX ENCODED"); break }
		ok, plain_bytes := tools.Crypt_aes_cbc(R.Errors(), false, aes_key, decoded_params, aes_iv); if !ok { break }
		return aes_iv, aes_key, plain_bytes
	}
	R.Error("CRYPTOAPI: FAILED TO DECRYPT RSA")
	return nil, nil, nil
}

func decrypt_request_body(R *Request) bool {
	cmds := []string{}
	params := []byte{}
	R.aes_iv, R.aes_key, params = DecryptRSA(R, R.temp_keys["securekey"], R.temp_keys["securedata"], R.rsa_key)
	cmds = strings.Split(string(params), ">>")
	for x := range cmds {
		z := strings.Split(cmds[x], ">")
		if len(z) != 2 { R.Error("PARAMETER IS BROKEN"); break }
		ok, decoded_input := tools.Decode_base64(R.Errors(), z[1]); if !ok { R.Error("NOT BASE64 ENCODED"); break }
		commandvalue := tools.Parse_sanitize(string(decoded_input))
		ok, key := tools.Parse_safe(R.Errors(), z[0]); if !ok { R.Error("POST PARAMS ARE BREAKING"); break }
		switch key {
			case "json": R.object = decoded_input
			case "action": R.Action = commandvalue
			case "deepkey": if !tools.Digest_valid(R.Errors(), commandvalue) { R.Error("INVALID DEEPKEY"); return false }; R.temp_keys["DEEPKEY"] = commandvalue
			case "sessionkey":
				if commandvalue != "guest" {
					if !tools.Digest_valid(R.Errors(), commandvalue) { R.Error("DIGEST INVALID ("+commandvalue+")"); return false }
					ok, R.user = CONTROLLER.do_auth(commandvalue, R.Username); if !ok { R.Error("REQUEST FAILED AUTHORIZATION ("+commandvalue+")"); return false }
					if R.user.Session().Origin != R.CheckOrigin() { R.Error("REQUEST ORIGIN DIFFERENT TO SESSION ORIGIN"); return false }
					R.Username = R.user.User()
				}
			default:
					value := ""
					for i := range commandvalue { if strings.Contains(tools.CharSet_select("beta"), string(commandvalue[i])) { value += string(commandvalue[i]) } }
					if commandvalue != value { R.Error(R.ID+"WARNING - BROKEN API PARAM ("+key+" - "+commandvalue+" - "+value+")") }
					R.input[key] = value
					R.Error("PARSED PARAM: "+key+" : "+value)
		}
	}
	return true
}

func CloseSession(net_user *OBJ) {
	(net_user.Session()).Destroy()
	for id, user := range CONTROLLER.api_key_index { if user == net_user { delete(CONTROLLER.api_key_index, id) } }
	for id, user := range CONTROLLER.session_key_index { if user == net_user { delete(CONTROLLER.session_key_index, id) } }
}
