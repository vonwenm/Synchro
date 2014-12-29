package synchro

import(
		"github.com/golangdaddy/go-tools-essential"
		"github.com/golangdaddy/go-zencode"
		"code.google.com/p/go.net/websocket"
		"crypto/rsa"
		"crypto/ecdsa"
		"crypto/x509"
		"math/big"
		"strings"
		"sync"
		"fmt"
		"reflect"
		)
	
type OBJ struct {
	id string
	Data map[string]interface{}
	Index map[string]*Index
	temp map[string]interface{}
	i *Infrastructure
	c chan bool
	z map[string]*Signature
	ok bool
	block bool
	sync.RWMutex
}

func (o *OBJ) ID() string { if len(o.id) != 64 { o.Digest() }; return o.id }

func (o *OBJ) CreateSignature(signer interface{}) *Signature {
	switch v := signer.(type) {
		case *OBJ:
			ok, private_key, _ := o.i.UnlockCertificate(o.i.RootAuthority, "ECDSA", ""); if !ok { tools.Quit_slow(o.i.logs, "CANT GET CACHED SUPER USER ECDSA KEY") }
			return o.NewSignature(o.id, o.i.RootAuthority, private_key)
		case *Request:
			R := signer.(*Request)
			ok, plain_bytes := R.PullAndDecrypt("KEYS", "ECDSA"); if !ok { break }
			private_key, err := x509.ParseECPrivateKey(plain_bytes); if err != nil { R.Error("CRYPTOAPI/REQUEST/SIGN: "+err.Error()); break }
			return o.NewSignature(o.id, R.user, private_key)
		default: fmt.Println(v)
	}
	o.i.logs<-"NEW SIGNATURE FAILED"; return nil
}

func (obj *OBJ) Digest() bool { if obj != nil { if obj.Data != nil { x := zencode.Encode(obj.Data); obj.id = tools.SHA_256(x); return true } }; obj.i.logs<-"DIGEST: FAILED TO HASH OBJECT"; return false }

func (o *OBJ) User() string { ok, u := o.StrData("USERNAME"); if ok { return u }; return "guest" }
func (o *OBJ) Type() string { ok, u := o.StrData("_TYPE"); if ok { return u }; return "DEFAULT" }
func (o *OBJ) Host() string { ok, u := o.StrData("_HOST"); if ok { return u }; return "ERROR" }
func (o *OBJ) Dest() string { ok, u := o.StrData("_DEST"); if ok { return u }; return "/errors/objects" }
func (o *OBJ) ShortID() string { if len(o.id) > 16 { return o.id[0:16] }; return o.id }

func (o *OBJ) StrData(k string) (bool, string) {
	if o == nil || o.Data == nil || o.Data[k] == nil { o.i.logs<-"StrData: DATA ERROR"; return false, "" }
	val, ok := o.Data[k].(string); if !ok { o.i.logs<-"StrData: FAILED TYPE ASSERT, SHOULD BE "+reflect.TypeOf(o.Data[k]).String(); return false, "" }
	return true, val
}
func (o *OBJ) Time() *tools.EasyTime { if o != nil { if o.Data != nil { val, ok := o.Data["_TIME"].(*tools.EasyTime); if ok { return val } } }; return nil }
func (user *OBJ) Session() *NetSession { return user.i.sessions[user.PublicName()] }
func (user *OBJ) Socket() *websocket.Conn {
	sesh := user.i.sessions[user.PublicName()]
	if sesh != nil { if sesh.websocket != nil { return sesh.websocket.socket } }
	return nil
}

func (user *OBJ) KeyID(t string) string {
	if user.Data != nil {
		if user.Data[t] != nil {
			switch v := user.Data[t].(type) {
				case map[string]interface{}:
					ok, ks := interface_to_map(user.i.logs, user.Data[t])
					if ok {
						hashed, ok := ks["PublicKeyHash"].(string); if ok { return hashed }
						user.i.logs<-"KEYID: FIELD TYPE ASSERT SHOULD BE: "+reflect.TypeOf(ks["PublicKeyHash"]).String()
					}
				case map[string]string:
					ks, ok := user.Data[t].(map[string]string); if ok { return ks["PublicKeyHash"] }
				default: user.i.logs<-"KEYID: MAP TYPE ASSERT SHOULD BE: "+reflect.TypeOf(user.Data[t]).String(); fmt.Println(v)
			}
		} else { user.i.logs<-"KEYID: USER "+t+" KEYSTORE IS NIL" }
	} else { user.i.logs<-"KEYID: USER DATA IS NIL" }
	return "ERROR"
}

func (user *OBJ) Details(i string) (bool, string) {
	if user.Data["DETAILS"] != nil {
		switch v := user.Data["DETAILS"].(type) {
			case map[string]string: return true, user.Data["DETAILS"].(map[string]string)[i]
			case map[string]interface{}:
				ok, m := interface_to_map(user.i.logs, user.Data["DETAILS"]); if !ok { break }
				val, ok := m[i].(string); if !ok { break }
				return true, val
			default : user.i.logs<-"*OBJ: USER DETAILS TYPE ASSERT SHOULD BE "+reflect.TypeOf(user.Data["DETAILS"]).String(); fmt.Println(v)
		}
	}
	user.i.logs<-"*OBJ: USER DETAILS NOT FOUND"
	return false, ""
}

func (o *OBJ) VerifyChild(signature *Signature, child_id string, public_key *ecdsa.PublicKey) bool {
	if public_key == nil {
		ok, key, _ := o.i.UnlockCertificate(o.i.RootAuthority, "ECDSA", "")
		if !ok { tools.Quit_slow(o.i.logs, "LOGIN: FAILED TO GET PUBLIC ECDSA FROM SUPER USER") }
		public_key = &key.PublicKey
	}
	a := new(big.Int); a.SetString(signature.A, 10)
	b := new(big.Int); b.SetString(signature.B, 10)
	_, h := tools.SHA(1, 0, o.ID()+child_id, nil)
	if !ecdsa.Verify(public_key, h, a, b) { o.i.logs<-"ECDSA: FAILED TO VERIFY CHILD "+child_id; return false }
	o.i.logs<-"ECDSA: SIGNATURE OK FOR PUBLIC KEY"
	return true
}

func (user *OBJ) Email() (bool, string) {
	x := user.i.PointerObjects(user.ID(), "EMAILVERIFICATION")
	if x != nil {
		for object_id, signature := range x {
			sig := &Signature{}
			if !tools.Decode_struct(user.i.logs, signature, sig) { break }
			if !user.VerifyChild(sig, object_id, nil) { break }
			ok, email_address := user.Details("EMAIL"); if !ok { break }
			return true, email_address
		}
	}
	user.i.Error("USER: FAILED TO FIND VALIDATION INFO FOR "+user.User())
	return false, ""
}

func (user *OBJ) PublicName() string {
	for {
		if user.Data == nil { break }
		ok, username := user.StrData("USERNAME"); if !ok { break }
		ok, host := user.StrData("_HOST"); if !ok { break }
		return username+"@"+host
	}
	user.i.logs<-"*OBJ: PUBLIC NAME DEFAULTING TO GUEST"
	return "guest"
}

func (user *OBJ) SendGuestInfo(socket *websocket.Conn, class string, value interface{}) bool {
	m := make(map[string]interface{})
	m["MESSAGE"] = tools.Uppercase(class)
	m["VALUE"] = value
	ok, o := user.i.NewObject("WS", m); if !ok { return false }
	err := websocket.JSON.Send(socket, o); if err == nil { return true }
	user.i.logs<-"*OBJ/SEND/GUEST: "+err.Error(); return false
}

func (user *OBJ) SendInfo(class string, value interface{}) bool {
	m := make(map[string]interface{})
	m["MESSAGE"] = tools.Uppercase(class)
	m["VALUE"] = value
	ok, o := user.i.NewObject("WS", m); if !ok { return false }
	socket := user.Socket()
	if socket == nil { user.i.logs<-"*OBJ/SEND/INFO: USER "+user.User()+" SOCKET IS NIL"; return false }
	err := websocket.JSON.Send(socket, o); if err == nil { return true }
	user.i.logs<-"*OBJ/SEND/INFO: "+err.Error()
	return false
}
		
func (user *OBJ) PublicRSA(logs chan string) (bool, *rsa.PublicKey) {
	if user.temp == nil { user.temp = make(map[string]interface{}) }
	if user.temp["PUBLICRSA"] != nil { key, ok := user.temp["PUBLICRSA"].(*rsa.PublicKey); if ok { return true, key } }
	for {
		ok, keystore := interface_to_map(user.i.logs, user.Data["RSA"]); if !ok { break }
		encoded, ok := keystore["EncodedPublicKey"].(string); if !ok { break }
		ok, decoded_key := tools.Decode_base64(logs, encoded); if !ok { break }
		key_interface, err := x509.ParsePKIXPublicKey(decoded_key); if err != nil { logs<-"SYNCHRO: "+err.Error(); break }
		pub_key, ok := key_interface.(*rsa.PublicKey); if !ok { break }
		user.temp["PUBLICRSA"] = pub_key
		return true, pub_key
	}
	logs<-"*OBJ: FAILED TO GET PUBLIC RSA KEY"
	return false, nil
}

func (user *OBJ) PublicECDSA(logs chan string) (bool, *ecdsa.PublicKey) {
	if user.temp == nil { user.temp = make(map[string]interface{}) }
	if user.temp["PUBLICECDSA"] != nil { key, ok := user.temp["PUBLICECDSA"].(*ecdsa.PublicKey); if ok { return true, key } }
	for {
		ok, keystore := interface_to_map(user.i.logs, user.Data["ECDSA"]); if !ok { break }
		encoded, ok := keystore["EncodedPublicKey"].(string); if !ok { break }
		ok, decoded_key := tools.Decode_base64(logs, encoded); if !ok { break }
		key_interface, err := x509.ParsePKIXPublicKey(decoded_key); if err != nil { logs<-"SYNCHRO: "+err.Error(); break }
		pub_key, ok := key_interface.(*ecdsa.PublicKey); if !ok { break }
		user.temp["PUBLICECDSA"] = pub_key
		return true, pub_key
	}
	logs<-"*OBJ: FAILED TO GET PUBLIC RSA KEY"
	return false, nil
}

func (object *OBJ) Send_json(user_slice []*OBJ, sesh_map map[string]*NetSession) bool {
	for {
		ok, msg := tools.Encode_json(object.i.logs, object); if !ok { break }
		if sesh_map == nil && user_slice == nil { break }
		if sesh_map != nil {
			for _, sesh := range sesh_map {
				if sesh.websocket == nil || sesh.websocket.socket == nil { continue }
				err := websocket.Message.Send(sesh.websocket.socket, string(msg))
				if err == nil { continue }
				object.i.logs<-"*OBJ/SEND/JSON: "+err.Error()
			}
		} else {
			for _, user := range user_slice {
				socket := user.Socket()
				if socket == nil { object.i.logs<-"WS MESSAGE FAILED : "+user.User(); continue };
				err := websocket.Message.Send(socket, string(msg))
				if err == nil { continue }
				object.i.logs<-err.Error(); object.i.logs<-"WS MESSAGE FAILED : "+user.User()
			}
		}
		return true
	}
	object.i.logs<-"*OBJ: SEND JSON WS MESSAGE FAIL"; return false
}

func (o *OBJ) GetScore(work_string string) (int, string) {
	pow := tools.SHA_256(o.id+tools.SHA_256(work_string))
	parts := strings.Split(pow, "/")
	if len(parts) > 2 {
			public_name := parts[0]
			if len(public_name) > 5 && strings.Contains(public_name, "@") {
				ok, tax := o.StrData("_DEST")
				if ok {
					target := tools.SHA_256(tax)
					main_score := 0
					for x := 0; x < 64; x++ { if pow[x] != target[63-x] { break }; main_score++ }
					score := 0
					for x := score; x < 64; x++ {
							switch string(pow[x]) {
								case "0": score += 1
								case "1": score += 2
								case "2": score += 3
								case "3": score += 4
								case "4": score += 5
								case "5": score += 6
								case "6": score += 7
								case "7": score += 8
								case "8": score += 9
								case "9": score += 10
								case "a": score += 11
								case "b": score += 12
								case "c": score += 13
								case "d": score += 14
								case "e": score += 15
								case "f": score += 16
							}
					}
					return main_score*score, pow
				}
			}
	}
	return 0, ""
}

type POW struct {
	// local username
	User string
	// host domain
	Host string
	// beneficiary object unique digest
	Bump string
	// valid sha2 result of work
	Work string
}
